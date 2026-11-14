# Publish a catalog

English | [Brazilian Portuguese](../pt-BR/guide/publishing.md)

A published catalog is a git repository started with `bme catalog init` or `bme catalog split` ([catalogs](catalogs.md#start-a-device-repository)). You sign its `catalog.json` with minisign at each release and tag the commit. Users register the raw `catalog.json` URL of a tag with your public key.

## What the repository holds

Git tracks the catalog directories, `notes/`, `catalog.json`, `catalog.json.minisig`, `README.md`, `LICENSE*`, `.github/`, `.gitignore` and `.gitattributes`. Everything else at the top level stays local, and `.gitignore` ignores firmware images, extracted modules, ACPI tables, archives, PDFs and key files in every directory. The scaffold `README.md` has the full list and the checks to make on `notes/` and `provenance/` files before you commit them: serial numbers, MAC addresses, vendor code and paths of your machine.

Keep the secret key outside the repository. `minisign` stores it in `~/.minisign/` by default.

The scaffold also writes `.github/workflows/validate.yml`. On every push and pull request it installs `bme` and runs `bme catalog index . --check` and `bme catalog validate .`. The scaffold `README.md` says which `bme` it installs.

## Release

```sh
# raise "version" in catalog.json
bme catalog index .
bme catalog validate .
minisign -S -s ~/.minisign/acme-x99.key -m catalog.json
minisign -V -H -p ~/.minisign/acme-x99.pub -m catalog.json
git add catalog.json catalog.json.minisig
git commit -m "chore(release): 0.2.0"
git tag v0.2.0
git push origin main v0.2.0
```

Sign last. The signature covers the exact bytes of `catalog.json`, so any later `bme catalog index` that changes the file invalidates it.

Change `version` only in a release commit. `bme catalog update` keeps every version it accepted with its manifest digest and refuses two cases:

- a version it already accepted, with different content: `version 0.2.0 was accepted with different content (<digest>)`;
- a version older than the newest one it accepted: `version 0.1.0 is older than the accepted 0.2.0 (rollback refused)`.

A record commit changes `catalog.json`, because the index holds the length and SHA-256 of every file. If two published states of `catalog.json` shared a version, a user who had accepted the first would be refused the second. Raising the version in each release commit, and publishing only tagged commits, gives every published version one content. A release you got wrong is replaced by a higher version, never by a re-tag.

## Sign

Install `minisign` from your distribution or from [jedisct1/minisign](https://github.com/jedisct1/minisign). Create a key pair once, outside the repository:

```sh
minisign -G -p ~/.minisign/acme-x99.pub -s ~/.minisign/acme-x99.key
```

`-G` asks for a password for the secret key (`-W` skips it). Sign `catalog.json` in the directory that holds it:

```sh
minisign -S -s ~/.minisign/acme-x99.key -m catalog.json
```

`minisign` writes the signature to `<file>.minisig`, here `catalog.json.minisig`, and `bme catalog update` downloads that name next to `catalog.json`. `bme` accepts a signature with these properties:

- It is prehashed: the second line of the file starts with `RU`. `minisign -S` makes one by default; `-l` makes a legacy signature (`RW`), which `bme` refuses.
- It carries the `trusted comment:` line and the global signature that follow it, which `minisign -S` always writes. A signature from OpenBSD `signify` has neither and is refused. Do not edit the trusted comment, since the global signature covers it; the untrusted comment can change freely.
- Its key id matches the public key the user gave.

## Consume a release

```sh
bme catalog add acme-x99 https://raw.githubusercontent.com/<owner>/<repo>/v0.2.0/catalog.json --trust-key <public key>
bme catalog update acme-x99
bme scan dump.bin --catalog acme-x99
```

`--trust-key` takes the base64 line of the public key (it starts with `RW`) or the path of the `.pub` file. `bme catalog update` downloads `catalog.json` and `catalog.json.minisig`, checks the signature, then fetches every indexed file at the URL of `catalog.json` with its file name replaced by the indexed path (`patches/B01.json` becomes `https://raw.githubusercontent.com/<owner>/<repo>/v0.2.0/patches/B01.json`). [Sources and trust](trust.md) lists the checks that follow.

- Register a tag, never a branch. A branch URL fails verification after any commit that changes `catalog.json` without a new signature, which includes every record commit. `-H` above makes `minisign` refuse a legacy signature the way `bme` does; minisign before 0.10 does not prehash by default.
- A catalog in a subdirectory of a repository uses the subdirectory in the URL, and `catalog.json.minisig` sits beside its `catalog.json`: `https://raw.githubusercontent.com/<owner>/<repo>/v0.2.0/boards/acme-x99/catalog.json`.
- `catalog add` refuses a registered alias. To move to a newer tag, run `bme catalog remove acme-x99`, add the new URL under the same alias, and update. `remove` keeps the accepted versions, so the rollback check still applies; `--purge` deletes them.

To use a catalog without a signature, clone it, check out the tag and load the directory:

```sh
git clone --branch v0.2.0 https://github.com/<owner>/<repo> acme-x99
bme scan dump.bin --catalog ./acme-x99 --allow-unsigned-local
```

A plan built from it records `unsigned-local` trust. A registered clone can still verify the signature: `bme catalog add acme-x99 ./acme-x99 --trust-key <public key>` checks `catalog.json.minisig` in place.

## Give users the public key outside the repository

A key committed next to `catalog.json` proves nothing: whoever can change the catalog can change the key beside it. Publish the public key where a reader can compare it with another source, such as the project page, a release note or a message from you, and tell users to pass it to `--trust-key`. `bme` never reads a key from a catalog.

## Link catalogs

The optional `repository` field of `catalog.json` names the repository (`bme catalog init --repository URL`), and `bme catalog merge` copies it into `sources` next to the commit and digest of each merged catalog; see [Share records between boards](catalogs.md#share-records-between-boards).

## Decision: no `github:` shorthand

`bme catalog add` takes a full `https://` URL. There is no `github:owner/repo[/path][@ref]` form. The URL shows the ref the user pinned, and `bme` applies the same checks to any host that serves raw files over HTTPS.
