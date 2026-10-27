from sentinelsoc.extensions import db
from sentinelsoc.models import User, AuditRecord
from sentinelsoc import cli

def test_create_admin_cli_secure_provisioning(app,monkeypatch):
    with app.app_context():
        User.query.filter_by(role="admin").delete();db.session.commit()
    answers=iter(["Long-CLI-Password-42!","Long-CLI-Password-42!"])
    monkeypatch.setattr(cli.getpass,"getpass",lambda _prompt:next(answers))
    result=app.test_cli_runner().invoke(args=["create-admin","--username","first-admin"])
    assert result.exit_code==0,result.output
    with app.app_context():
        admin=User.query.filter_by(username="first-admin").one()
        assert admin.role=="admin" and admin.check_password("Long-CLI-Password-42!")
        assert AuditRecord.query.filter_by(action="admin.provisioned").count()==1

