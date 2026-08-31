"""Explicit development database commands.

Every destructive operation on the simulator's database lives here and nowhere
else. Importing ``app`` creates missing tables and seeds *empty* ones; it never
drops or deletes anything. If you want data gone, you ask for it by name:

    python manage.py status           show the schema and row counts
    python manage.py init             create missing tables, seed if empty
    python manage.py reset-demo       replace the marketplace/demo-file rows
    python manage.py drop-legacy      drop superseded Milestone 1/2 tables
    python manage.py reap-state       delete stale ransomware run state
    python manage.py reset-database   DESTRUCTIVE full rebuild (see below)

``reset-database`` is the reproducible-experiment command: it drops every table
this build knows about (plus any superseded ones left behind), recreates the
current schema and reseeds the synthetic baseline content -- the marketplace
products and the demo-file catalogue -- and nothing else. Recorded telemetry,
credential-interaction metadata and ransomware run state are **not** reseeded,
because there is no synthetic baseline for them: an experiment must start from
an empty event table or its numbers mean nothing. Run it before a formal run to
guarantee that every run starts from an identical schema and identical seed data:

    python manage.py reset-database --yes

``reset-all`` is kept as an alias for the same operation so existing notes and
scripts keep working.

This is deliberately not a migration framework. The project is a SQLite-backed
teaching demo with no production data and no schema history worth preserving,
so a named reset is a more honest tool than an Alembic chain nobody runs. Each
destructive command asks for confirmation unless ``--yes`` is passed.
"""

import argparse
import sys

import sqlalchemy

import app as app_module
import telemetry_ledger
from sandbox.ransomware_state import DEFAULT_MAX_AGE_SECONDS

db = app_module.db
DESTRUCTIVE = ("reset-demo", "drop-legacy", "reap-state", "reset-database",
               "reset-all")


def _table_names():
    return sorted(sqlalchemy.inspect(db.engine).get_table_names())


def cmd_status(_args):
    print("database : %s" % app_module.app.config["SQLALCHEMY_DATABASE_URI"])
    print("tables   : %s" % (", ".join(_table_names()) or "(none)"))
    for model in (app_module.Product, app_module.DemoFile,
                  app_module.CredentialInteraction, app_module.SecurityEvent,
                  app_module.RansomwareRunState):
        print("  %-24s %d row(s)" % (model.__tablename__, model.query.count()))
    ledger = telemetry_ledger.table()
    if ledger is not None:
        claims = db.session.execute(
            sqlalchemy.select(sqlalchemy.func.count()).select_from(ledger)).scalar()
        print("  %-24s %d claim(s)" % (telemetry_ledger.TABLE_NAME, claims))
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


def cmd_reap_state(args):
    """Delete stale ransomware run state, and release the claims of that age.

    Age-based only: neither this command nor the functions it calls accept a
    session id, so a specific learner's row can never be singled out. Nothing
    in ``security_event`` is touched -- recorded telemetry survives the reap.
    """
    reaped = app_module.reap_ransomware_state(args.max_age, dry_run=args.dry_run)
    verb = "would delete" if args.dry_run else "deleted"
    print("%s %d stale ransomware run-state row(s) older than %.0fs"
          % (verb, len(reaped), float(args.max_age)))
    for row in reaped:
        print("  %s  %s  age=%.0fs" % (row["session_label"], row["state"],
                                       row["age_seconds"]))
    if not args.dry_run:
        released = telemetry_ledger.reap_claims(db.session, args.max_age)
        db.session.commit()
        print("released %d stale progression-milestone claim(s)" % released)
    return 0


def cmd_reset_database(_args):
    """Drop everything, rebuild the current schema, reseed synthetic baseline."""
    db.drop_all()
    app_module.drop_legacy_tables()
    app_module.init_db()
    print("all tables dropped and rebuilt; synthetic baseline content seeded")
    print("tables: %s" % ", ".join(_table_names()))
    return 0


COMMANDS = {
    "status": cmd_status,
    "init": cmd_init,
    "reset-demo": cmd_reset_demo,
    "drop-legacy": cmd_drop_legacy,
    "reap-state": cmd_reap_state,
    "reset-database": cmd_reset_database,
    # Alias, kept so older notes and scripts keep working.
    "reset-all": cmd_reset_database,
}

#: Printed before the confirmation prompt so an operator sees what they are
#: about to lose, not merely that something is "destructive".
WARNINGS = {
    "reset-demo": "replaces every marketplace product and demo-file row",
    "drop-legacy": "drops superseded Milestone 1/2 tables and their contents",
    "reap-state": "deletes ransomware run state older than the given age",
    "reset-database": "DROPS EVERY TABLE, including all recorded telemetry, "
                      "credential-interaction metadata and ransomware run "
                      "state, then recreates the schema and reseeds only the "
                      "synthetic baseline content. This is not reversible.",
    "reset-all": "alias for reset-database; DROPS EVERY TABLE",
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--yes", action="store_true",
                        help="skip the confirmation prompt for destructive commands")
    parser.add_argument("--max-age", type=float, default=DEFAULT_MAX_AGE_SECONDS,
                        dest="max_age",
                        help="reap-state: staleness threshold in seconds "
                             "(default %d)" % DEFAULT_MAX_AGE_SECONDS)
    parser.add_argument("--dry-run", action="store_true",
                        help="reap-state: report the selection, delete nothing")
    args = parser.parse_args(argv)

    gated = args.command in DESTRUCTIVE and not (
        args.command == "reap-state" and args.dry_run)
    if gated and not args.yes:
        uri = app_module.app.config["SQLALCHEMY_DATABASE_URI"]
        print("WARNING: %r %s" % (args.command, WARNINGS[args.command]))
        answer = input("%r will DESTROY data in %s. Type 'yes' to continue: "
                       % (args.command, uri))
        if answer.strip().lower() != "yes":
            print("aborted; nothing was changed")
            return 1

    with app_module.app.app_context():
        return COMMANDS[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
