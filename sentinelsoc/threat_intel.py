"""Explicit analyst-initiated AlienVault OTX IPv4/IPv6 enrichment."""
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from flask import current_app
from .extensions import db
from .models import ThreatIntelCache

class OTXProvider:
    name="AlienVault OTX"
    base_url="https://otx.alienvault.com/api/v1/indicators"
    def lookup_ip(self, indicator, api_key, timeout=4):
        address=ipaddress.ip_address(indicator)
        version="IPv4" if address.version==4 else "IPv6"
        safe=urllib.parse.quote(str(address),safe="")
        request=urllib.request.Request(f"{self.base_url}/{version}/{safe}/general",
            headers={"X-OTX-API-KEY":api_key,"Accept":"application/json","User-Agent":"SentinelSOC/1.0"})
        with urllib.request.urlopen(request,timeout=timeout) as response:
            if response.status==429:return {"status":"unavailable","retry_after":60,"reason":"provider_rate_limited"}
            payload=json.loads(response.read(262_145).decode("utf-8"))
        info=payload.get("pulse_info") if isinstance(payload,dict) else None
        if not isinstance(info,dict) or not isinstance(info.get("count"),int):
            return {"status":"unknown","reason":"unrecognized_provider_response"}
        pulses=[]
        for item in (info.get("pulses") or [])[:5]:
            if isinstance(item,dict):pulses.append({"id":str(item.get("id", ""))[:80],"name":str(item.get("name", ""))[:160]})
        count=max(0,info["count"])
        return {"status":"positive" if count else "negative","pulse_count":count,"pulses":pulses,
            "note":"Positive means OTX returned associated pulses. Negative means none were returned; it is not proof an indicator is benign."}

def enrich_ip(indicator,provider=None):
    try:canonical=str(ipaddress.ip_address(indicator))
    except ValueError:raise ValueError("indicator must be an IPv4 or IPv6 address")
    provider=provider or OTXProvider();now=datetime.now(timezone.utc)
    cached=ThreatIntelCache.query.filter_by(provider=provider.name,indicator=canonical).first()
    if cached and _as_utc(cached.expires_at)>now:
        return {"indicator":canonical,"provider":provider.name,"status":cached.status,"result":cached.result_json,
            "enriched_at":cached.fetched_at.isoformat(),"cached":True}
    api_key=current_app.config.get("OTX_API_KEY","")
    if not api_key:return {"indicator":canonical,"provider":provider.name,"status":"unavailable","result":{"reason":"provider_not_configured"},"enriched_at":now.isoformat(),"cached":False}
    try:
        result=provider.lookup_ip(canonical,api_key)
        status=result.get("status","unknown")
    except urllib.error.HTTPError as exc:
        if exc.code==429:result={"status":"unavailable","reason":"provider_rate_limited","retry_after":_retry_after(exc)}
        elif exc.code in {401,403}:result={"status":"unavailable","reason":"provider_authentication_failed"}
        else:result={"status":"unavailable","reason":"provider_http_error","http_status":exc.code}
        status=result["status"]
    except (urllib.error.URLError,TimeoutError,ConnectionError):
        result={"status":"unavailable","reason":"provider_unreachable"};status="unavailable"
    except (ValueError,json.JSONDecodeError,UnicodeDecodeError):
        result={"status":"unknown","reason":"invalid_provider_response"};status="unknown"
    except Exception as exc:
        current_app.logger.warning("Threat provider failed: %s",type(exc).__name__)
        result={"status":"unavailable","reason":"provider_error"};status="unavailable"
    ttl=current_app.config.get("THREAT_INTEL_CACHE_SECONDS",21600)
    if status in {"unavailable","unknown"}:ttl=min(ttl,60)
    if result.get("retry_after"):ttl=min(ttl,max(1,min(int(result["retry_after"]),3600)))
    if cached:
        cached.status=status;cached.result_json=result;cached.fetched_at=now;cached.expires_at=now+timedelta(seconds=ttl)
    else:
        db.session.add(ThreatIntelCache(provider=provider.name,indicator=canonical,status=status,result_json=result,
            fetched_at=now,expires_at=now+timedelta(seconds=ttl)))
    db.session.commit()
    return {"indicator":canonical,"provider":provider.name,"status":status,"result":result,"enriched_at":now.isoformat(),"cached":False}

def _as_utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def _retry_after(error):
    value=error.headers.get("Retry-After") if error.headers else None
    try:return min(max(int(value),1),3600)
    except (TypeError,ValueError):return 60
