# gemato: Top-level Manifest finding routine
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import errno
import os
import os.path

import gemato.compression
import gemato.manifest


def find_top_level_manifest(path='.'):
    """
    Find top-level Manifest file that covers @path (defaults
    to the current directory). Returns the path to the Manifest
    or None.
    """

    cur_path = path
    last_found = None
    original_dev = None
    m = gemato.manifest.ManifestFile()

    root_st = os.stat('/')

    while True:
        st = os.stat(cur_path)

        # verify that we are not crossing device boundaries
        if original_dev is None:
            original_dev = st.st_dev
        elif original_dev != st.st_dev:
            break

        m_path = os.path.join(cur_path, 'Manifest')
        for m_path in (gemato.compression
                .get_potential_compressed_names(m_path)):
            try:
                with (gemato.compression
                        .open_potentially_compressed_path(m_path, 'r',
                            encoding='utf8')) as f:
                    fst = os.fstat(f.fileno())
                    if fst.st_dev != original_dev:
                        return last_found

                    m.load(f, verify_openpgp=False)
            except IOError as e:
                if e.errno != errno.ENOENT:
                    raise
            else:
                # check if the initial path is ignored
                relpath = os.path.relpath(path, cur_path)
                if relpath == '.':
                    relpath = ''
                fe = m.find_path_entry(relpath)
                if fe is not None and fe.tag == 'IGNORE':
                    return last_found

                last_found = m_path
                break

        # check if we reached root directory
        if st.st_dev == root_st.st_dev and st.st_ino == root_st.st_ino:
            break

        # try the parent directory
        cur_path = os.path.join(cur_path, '..')

    return last_found
