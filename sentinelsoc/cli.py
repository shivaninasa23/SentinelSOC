import getpass
import click
from .extensions import db
from .models import User, DetectionRule, SecurityEvent, Alert
from .services import audit
from datetime import datetime, timedelta, timezone

def register_commands(app):
    @app.cli.command("init-db")
    def init_db():
        """Create tables and seed the documented detection rule."""
        db.create_all()
        defaults=[
            ("auth.bruteforce","Repeated authentication failures from one source","Failures from one IP in a rolling window.",app.config["BRUTE_FORCE_THRESHOLD"],app.config["BRUTE_FORCE_WINDOW_SECONDS"]),
            ("auth.account_failures","Repeated failures against one account","Failures for one username across sources.",5,60),
            ("auth.password_spray","Password spraying indicator","One IP failing authentication across distinct accounts.",5,60),
            ("auth.success_after_failures","Successful login after repeated failures","Success following failures against one account.",3,300),
        ]
        for rule_id,name,description,threshold,window in defaults:
            if not db.session.get(DetectionRule,rule_id):db.session.add(DetectionRule(id=rule_id,name=name,description=description,threshold=threshold,window_seconds=window))
        db.session.commit()
        click.echo("Database initialized.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    def create_admin(username):
        """Provision an administrator with an interactively entered password."""
        if User.query.filter_by(role="admin").first(): raise click.ClickException("An administrator already exists.")
        if not username or len(username)>80 or User.query.filter_by(username=username).first(): raise click.ClickException("Username is invalid or already in use.")
        password=getpass.getpass("Administrator password (12+ characters): ")
        confirm=getpass.getpass("Confirm password: ")
        if len(password)<12 or password!=confirm: raise click.ClickException("Passwords must match and contain at least 12 characters.")
        user=User(username=username,role="admin");user.set_password(password);db.session.add(user);db.session.flush()
        audit("admin.provisioned",username,user.id);db.session.commit();click.echo(f"Administrator '{username}' created.")

    @app.cli.command("retain-events")
    @click.option("--days",type=click.IntRange(1,3650),default=90,show_default=True)
    @click.option("--apply",is_flag=True,help="Delete eligible records. Without this flag, only report the count.")
    def retain_events(days,apply):
        """Prune old events while retaining every alert-linked evidence event."""
        cutoff=datetime.now(timezone.utc)-timedelta(days=days)
        old=SecurityEvent.query.filter(SecurityEvent.occurred_at<cutoff).all()
        protected={event_id for alert in Alert.query.with_entities(Alert.event_ids).all() for event_id in (alert[0] or [])}
        eligible=[event for event in old if event.event_id not in protected]
        click.echo(f"Expired candidates: {len(old)}; alert evidence retained: {len(old)-len(eligible)}; eligible for deletion: {len(eligible)}.")
        if not apply:
            click.echo("Dry run only. Pass --apply to delete eligible event rows.")
            return
        deleted=len(eligible)
        for event in eligible:db.session.delete(event)
        audit("events.retention_applied",metadata={"days":days,"deleted":deleted,"evidence_retained":len(old)-deleted})
        db.session.commit();click.echo(f"Deleted {deleted} expired event rows.")
