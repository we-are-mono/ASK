# Record which checkout files a recipe builds from, so a test run can refuse
# an image its checkout did not build (tools/ask_orch/manifest.py).
#
# The record lists the recipe, its local SRC_URI entries, its external source
# tree and ASK_PROVENANCE_PATHS (checkout-relative), each file by content. It
# is taken before configure -- for an image, before its rootfs -- and taken
# again whenever the set of those files or one of them changes, so everything
# the recipe builds afterwards is built from what it records. ${PN}-provenance
# carries it into the image, pulled in by ASK_PROVENANCE_OWNER; a source tree
# the build unpacked carries it too, for the host tests that compile from it.

ASK_PROVENANCE_PATHS ??= ""
ASK_PROVENANCE_OWNER ??= "${PN}"
ASK_PROVENANCE_DIR = "${WORKDIR}/ask-provenance"
ASK_PROVENANCE_UNPACKED = "${WORKDIR}/ask-provenance-unpacked.json"
# manifest.IMAGE_DIR names the same place for the test harness.
ASK_PROVENANCE_INSTALLDIR = "${datadir}/ask/provenance"
ASK_PROVENANCE_MODULE = "tools/ask_orch/build_record.py"

# Which files a recipe builds from is git's answer, and it changes without the
# recipe changing: a file added, removed or newly ignored. Bitbake's parse
# cache would keep the first answer.
BB_DONT_CACHE = "1"

def ask_provenance_root(d):
    import os
    return os.path.realpath(d.getVar('ASK_SRCROOT'))
# The checkout's location is no input: the record and its checksums are relative.
ask_provenance_root[vardepsexclude] = "ASK_SRCROOT"

def ask_provenance_module(d):
    import importlib.util, os
    path = os.path.join(ask_provenance_root(d), d.getVar('ASK_PROVENANCE_MODULE'))
    spec = importlib.util.spec_from_file_location('ask_build_record', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def ask_provenance_relative(d, candidates):
    import os
    root = ask_provenance_root(d)
    inputs = set()
    for candidate in filter(None, candidates):
        relative = os.path.relpath(os.path.realpath(candidate), root)
        if relative != os.pardir and not relative.startswith(os.pardir + os.sep):
            inputs.add(relative)
    return sorted(inputs)

def ask_provenance_local(d):
    """The local SRC_URI entries inside the checkout, relative to it."""
    fetch = bb.fetch2.Fetch([], d, cache=False, localonly=True)
    # A local-only fetcher holds None for every other kind of URL.
    local = [fetch.ud.get(url) for url in fetch.urls]
    return ask_provenance_relative(d, [ud.method.localpath(ud, d) for ud in local
                                       if ud and isinstance(ud.method, bb.fetch2.local.Local)])

def ask_provenance_inputs(d):
    """Every input inside the checkout, relative to it."""
    import os
    root = ask_provenance_root(d)
    return sorted(set(ask_provenance_local(d)) | set(ask_provenance_relative(d,
        [d.getVar('FILE'), d.getVar('EXTERNALSRC')]
        + [os.path.join(root, path) for path in d.getVar('ASK_PROVENANCE_PATHS').split()])))

def ask_provenance_checksums(d, inputs):
    # Each file a record of `inputs` lists, by its path from the checkout
    # ("/./" puts that path in the task hash), so a rename, an addition, a
    # removal or a change of ignore rules re-records as surely as an edit
    # does; and the code that records it.
    import os
    root = ask_provenance_root(d)
    # No inputs are no files; git would answer with the whole checkout.
    names = ask_provenance_module(d).names(root, inputs) if inputs else []
    return ' '.join('%s/./%s:True' % (root, name)
                    for name in names + [d.getVar('ASK_PROVENANCE_MODULE')]
                    if os.path.isfile(os.path.join(root, name)))

# The local sources as do_unpack and do_patch begin to read them. A record
# taken after them that differs means one changed under the build. do_unpack
# runs again whenever this record would change, so it is never stale.
python ask_provenance_unpack() {
    import os
    local = ask_provenance_local(d)
    snapshot = d.getVar('ASK_PROVENANCE_UNPACKED')
    if not local:
        if os.path.exists(snapshot):
            os.remove(snapshot)
        return
    module = ask_provenance_module(d)
    with open(snapshot, 'wb') as stream:
        stream.write(module.encode(module.record(ask_provenance_root(d), d.getVar('PN'), local)))
}
do_unpack[prefuncs] += "ask_provenance_unpack"
do_unpack[file-checksums] += "${@ask_provenance_checksums(d, ask_provenance_local(d))}"

python do_ask_provenance() {
    import json, os
    module = ask_provenance_module(d)
    root = ask_provenance_root(d)
    unpacked = d.getVar('ASK_PROVENANCE_UNPACKED')
    if os.path.exists(unpacked):
        with open(unpacked, 'rb') as stream:
            then = stream.read()
        if module.encode(module.record(root, d.getVar('PN'), json.loads(then)['paths'])) != then:
            # The unpacked tree is stale whatever the stamps say: the next
            # build has to unpack again rather than meet this again.
            os.remove(unpacked)
            bb.build.clean_stamp('do_unpack', d)
            bb.fatal('a local source of %s changed while the build read it; build again'
                     % d.getVar('PN'))
    data = module.encode(module.record(root, d.getVar('PN'), ask_provenance_inputs(d)))
    with open(os.path.join(d.getVar('ASK_PROVENANCE_DIR'), d.getVar('PN') + '.json'), 'wb') as stream:
        stream.write(data)
    # An external source tree is the checkout itself, and an image unpacks none.
    if not d.getVar('EXTERNALSRC') and not bb.data.inherits_class('image', d):
        with open(os.path.join(d.getVar('S'), module.TREE_FILE), 'wb') as stream:
            stream.write(data)
}
do_ask_provenance[cleandirs] = "${ASK_PROVENANCE_DIR}"
do_ask_provenance[file-checksums] = "${@ask_provenance_checksums(d, ask_provenance_inputs(d))}"
# externalsrc deletes do_patch, and with it this ordering; its tree is read
# from the checkout only after this records it.
addtask ask_provenance after do_patch before do_configure

ask_provenance_install() {
    install -D -m 0644 ${ASK_PROVENANCE_DIR}/${PN}.json ${D}${ASK_PROVENANCE_INSTALLDIR}/${PN}.json
}

ask_provenance_rootfs() {
    install -D -m 0644 ${ASK_PROVENANCE_DIR}/${PN}.json ${IMAGE_ROOTFS}${ASK_PROVENANCE_INSTALLDIR}/${PN}.json
}

PACKAGES:prepend = "${@'' if bb.data.inherits_class('image', d) else d.getVar('PN') + '-provenance '}"
FILES:${PN}-provenance = "${ASK_PROVENANCE_INSTALLDIR}"

python () {
    if bb.data.inherits_class('image', d):
        bb.build.addtask('do_ask_provenance', 'do_rootfs', None, d)
        d.appendVar('ROOTFS_POSTPROCESS_COMMAND', ' ask_provenance_rootfs')
    else:
        d.appendVarFlag('do_install', 'postfuncs', ' ask_provenance_install')
        d.appendVar('RDEPENDS:' + d.getVar('ASK_PROVENANCE_OWNER'), ' ${PN}-provenance')
}
