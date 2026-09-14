"""Find and merge duplicate ``hashes`` rows so the unique constraint can be created.

Migration f3b8c1a7d942 adds uq_hashes_sub_ciphertext_hash_type. If the table
already contains two rows sharing (sub_ciphertext, hash_type) it cannot, so the
migration warns, skips the constraint, and lets the rest of the chain apply. This
repairs the data; the next upgrade then creates the constraint.

A duplicate is the same sub_ciphertext AND the same hash_type. The same 32-hex
string uploaded once as MD5 and once as NTLM is NOT a duplicate -- it is two
different hashes that happen to share a ciphertext, and the constraint is on the
pair precisely so that stays legal. This tool never touches those.

Raw SQL throughout, and no create_app(). A database that still has duplicates is
one where the migration declined to finish, so it may sit below head while
hashview.models describes head; going through the ORM would fail on columns that
do not exist yet. It reads hashview/config.conf for the connection exactly as the
app does, or takes --database-uri.

    python scripts/repair_duplicate_hashes.py --report      # read-only, default
    python scripts/repair_duplicate_hashes.py --apply       # merge the unambiguous
    python scripts/repair_duplicate_hashes.py --interactive # decide the rest

Back up the database first. --report changes nothing and is safe to run anywhere.
"""
import argparse
import configparser
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.engine.url import make_url  # noqa: E402

from hashview.utils.dedupe import (  # noqa: E402
    classify_group,
    duplicate_summary,
    find_duplicate_groups,
    group_hashfiles,
    group_rows,
    merge_group,
)

_CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       'hashview', 'config.conf')


def database_uri(override=None):
    """The app's own connection string, or --database-uri."""
    if override:
        return override
    if not os.path.isfile(_CONFIG):
        sys.exit(f'No {_CONFIG} and no --database-uri; nothing to connect to.')
    parsed = configparser.ConfigParser()
    parsed.read(_CONFIG)
    section = parsed['database']
    return ('mysql+mysqlconnector://' + section['username'] + ':' + section['password']
            + '@' + section['host'] + '/hashview?charset=utf8mb4')


def _fmt_row(row, hashfiles, show_ciphertext=False):
    """One duplicate row, with everything that bears on keeping it."""
    bits = [f'id={row["id"]}']
    if show_ciphertext:
        # Only when the group's ciphertexts DIFFER -- that difference is the whole
        # reason the group is a conflict, so it has to be visible per row.
        bits.append(f'ciphertext={row["ciphertext"][:60]!r}')
    if row['cracked']:
        bits.append(f'CRACKED plaintext={row["plaintext"]!r}')
        if row['recovered_at']:
            bits.append(f'at {row["recovered_at"]}')
    else:
        bits.append('not cracked')
    bits.append(f'{row["links"]} hashfile link(s)')
    if row['notifications']:
        bits.append(f'{row["notifications"]} alert(s)')
    line = '      ' + ', '.join(bits)
    for hashfile_id, name, username in hashfiles.get(row['id'], [])[:5]:
        line += f'\n        - hashfile {hashfile_id} ({name or "?"}) as {username or "(no username)"}'
    return line


def _show_group(index, total, group, rows, hashfiles, kind, keeper, reason):
    print(f'\n  [{index}/{total}] hash_type={group["hash_type"]} '
          f'sub_ciphertext={group["sub_ciphertext"]} -- {group["count"]} rows')
    mixed = len({r['ciphertext'] for r in rows}) > 1
    if not mixed:
        print(f'      ciphertext: {rows[0]["ciphertext"][:70]}')
    for row in rows:
        print(_fmt_row(row, hashfiles, show_ciphertext=mixed))
    if kind == 'auto':
        print(f'      -> keep id={keeper}, merge the rest ({reason})')
    else:
        print(f'      -> NEEDS YOU: {reason}')


def _choose(rows):
    """Ask which row to keep. Returns an id, or None to skip this group."""
    valid = {str(r['id']) for r in rows}
    while True:
        try:
            answer = input('      keep which id? (or "s" to skip, "q" to stop) ').strip()
        except EOFError:
            # Piped or otherwise non-interactive stdin. Stop cleanly and keep
            # what has already been decided, rather than dying on a traceback
            # part-way through a repair.
            print('\n      no more input; stopping.')
            raise KeyboardInterrupt from None
        if answer in ('s', 'S', ''):
            return None
        if answer in ('q', 'Q'):
            raise KeyboardInterrupt
        if answer in valid:
            return int(answer)
        print(f'      not one of {sorted(valid)}')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--report', action='store_true',
                      help='list duplicates and what would happen; changes nothing (default)')
    mode.add_argument('--apply', action='store_true',
                      help='merge every group the data decides; leave conflicts alone')
    mode.add_argument('--interactive', action='store_true',
                      help='merge the unambiguous, then ask about each conflict')
    parser.add_argument('--yes', action='store_true',
                        help='skip the confirmation prompt before writing')
    parser.add_argument('--database-uri', help='override the connection from config.conf')
    parser.add_argument('--limit', type=int, help='only look at the first N groups')
    args = parser.parse_args()

    engine = create_engine(database_uri(args.database_uri))
    safe = make_url(str(engine.url)).render_as_string(hide_password=True)
    print(f'Database: {safe}')

    with engine.connect() as conn:
        groups_count, excess = duplicate_summary(conn)
        if not groups_count:
            print('\nNo duplicate (sub_ciphertext, hash_type) pairs. '
                  'Re-run the app or `flask db upgrade` to create the constraint.')
            return 0
        print(f'\n{groups_count} duplicate group(s), {excess} row(s) would be removed.')

        groups = find_duplicate_groups(conn, limit=args.limit)
        plans, conflicts = [], []
        for position, group in enumerate(groups, 1):
            rows = group_rows(conn, group['hash_type'], group['sub_ciphertext'])
            kind, keeper, reason = classify_group(rows)
            hashfiles = group_hashfiles(conn, [r['id'] for r in rows])
            _show_group(position, len(groups), group, rows, hashfiles, kind, keeper, reason)
            (plans if kind == 'auto' else conflicts).append((group, rows, keeper, reason))

        if args.report or not (args.apply or args.interactive):
            print(f'\nReport only, nothing changed. {len(plans)} group(s) can be merged '
                  f'automatically; {len(conflicts)} need a decision.')
            print('Re-run with --apply to merge the first set, '
                  '--interactive to decide the rest.')
            return 0

        if not args.yes:
            print(f'\nAbout to merge {len(plans)} group(s), removing '
                  f'{sum(len(r) - 1 for _g, r, _k, _x in plans)} row(s). '
                  'Back up the database first.')
            try:
                if input('Continue? [y/N] ').strip().lower() not in ('y', 'yes'):
                    print('Nothing changed.')
                    return 0
            except EOFError:
                print('\nNo confirmation received (non-interactive stdin); '
                      'nothing changed. Pass --yes to proceed.')
                return 1

        # Merging is one transaction: a partial merge is the dangerous state,
        # because a link row left pointing at a deleted hash makes its job
        # undispatchable and reads as "nothing left to crack".
        merged = 0
        with conn.begin():
            for _group, rows, keeper, _reason in plans:
                merge_group(conn, keeper, [r['id'] for r in rows if r['id'] != keeper])
                merged += 1
            if args.interactive and conflicts:
                print(f'\n{len(conflicts)} group(s) need a decision. '
                      'Pick the row to KEEP; the others are merged into it.')
                for group, rows, _keeper, reason in conflicts:
                    hashfiles = group_hashfiles(conn, [r['id'] for r in rows])
                    print(f'\n  hash_type={group["hash_type"]} '
                          f'sub_ciphertext={group["sub_ciphertext"]} -- {reason}')
                    mixed = len({r['ciphertext'] for r in rows}) > 1
                    for row in rows:
                        print(_fmt_row(row, hashfiles, show_ciphertext=mixed))
                    try:
                        chosen = _choose(rows)
                    except KeyboardInterrupt:
                        print('\n      stopping; everything decided so far is kept.')
                        break
                    if chosen is None:
                        continue
                    merge_group(conn, chosen, [r['id'] for r in rows if r['id'] != chosen])
                    merged += 1

        remaining = duplicate_summary(conn)[0]
        print(f'\nMerged {merged} group(s). {remaining} duplicate group(s) remain.')
        if remaining:
            print('Re-run with --interactive to decide the rest; the constraint is not '
                  'created until none remain.')
        else:
            print('Now restart Hashview (or run `flask db upgrade`) to create '
                  'uq_hashes_sub_ciphertext_hash_type.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
