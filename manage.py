"""Explicit development database commands.

Every destructive operation on the simulator's database lives here and nowhere
else. Importing ``app`` creates missing tables and seeds *empty* ones; it never
drops or deletes anything. If you want data gone, you ask for it by name:

    python manage.py status         show the schema and row counts
    python manage.py init           create missing tables, seed if empty
    python manage.py reset-demo     replace the marketplace/demo-file rows
    python manage.py drop-legacy    drop superseded Milestone 1/2 tables
    python manage.py reset-all      drop every table and rebuild from scratch

This is deliberately not a migration framework. The project is a SQLite-backed
teaching demo with no production data and no schema history worth preserving,
so a named reset is a more honest tool than an Alembic chain nobody runs. Each
destructive command asks for confirmation unless ``--yes`` is passed.
"""

import argparse
import sys

import sqlalchemy

import app as app_module

db = app_module.db
DESTRUCTIVE = ("reset-demo", "drop-legacy", "reset-all")


def _table_names():
    return sorted(sqlalchemy.inspect(db.engine).get_table_names())


def cmd_status(_args):
    print("database : %s" % app_module.app.config["SQLALCHEMY_DATABASE_URI"])
    print("tables   : %s" % (", ".join(_table_names()) or "(none)"))
    for model in (app_module.Product, app_module.DemoFile,
                  app_module.CredentialInteraction, app_module.SecurityEvent):
        print("  %-24s %d row(s)" % (model.__tablename__, model.query.count()))
    legacy = [t for t in app_module.LEGACY_TABLES if t in _table_names()]
    print("legacy tables present: %s" % (", ".join(legacy) or "none"))
    return 0


def cmd_init(_args):
    seeded = app_module.init_db()
    print("schema created/verified; demo content %s"
          % ("seeded" if seeded else "left untouched (already present)"))
    return 0


def cmd_reset_demo(_args):
    app_module.init_db(force_reseed=True)
    print("demo products and demo files replaced")
    return 0


def cmd_drop_legacy(_args):
    dropped = app_module.drop_legacy_tables()
    print("dropped: %s" % (", ".join(dropped) or "nothing (no legacy tables)"))
    return 0


def cmd_reset_all(_args):
    db.drop_all()
    app_module.drop_legacy_tables()
    app_module.init_db()
    print("all tables dropped and rebuilt; demo content seeded")
    return 0


COMMANDS = {
    "status": cmd_status,
    "init": cmd_init,
    "reset-demo": cmd_reset_demo,
    "drop-legacy": cmd_drop_legacy,
    "reset-all": cmd_reset_all,
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--yes", action="store_true",
                        help="skip the confirmation prompt for destructive commands")
    args = parser.parse_args(argv)

    if args.command in DESTRUCTIVE and not args.yes:
        uri = app_module.app.config["SQLALCHEMY_DATABASE_URI"]
        answer = input("%r will DESTROY data in %s. Type 'yes' to continue: "
                       % (args.command, uri))
        if answer.strip().lower() != "yes":
            print("aborted; nothing was changed")
            return 1

    with app_module.app.app_context():
        return COMMANDS[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
