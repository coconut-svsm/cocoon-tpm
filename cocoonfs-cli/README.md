# Cocoon TPM project - `cocoonfs-cli` crate

CLI program to work with CocoonFs image files -- create CocoonFs images and read, write, list and remove files in
existing images.

CocoonFs is a special purpose filesystem format designed for the secure storage of sensitive data in e.g. a TEE
setting. In addition to its primary design focus on strong security properties, the format implements support for some
features of particular relevance to the intended use-case, such as support for keyless storage volume provisiong and
robustness against service interruptions by means of a journal.

For the format specification, refer to file `cocoonfs-format.md` distributed with the code, see
[here](https://coconut-svsm.github.io/cocoon-tpm/cocoonfs/cocoonfs-format.html) for a rendered version.

A note ahead: all operations, except for `write-mkfsinfo-header`, require access to the filesystem key. That may either
get provided directly on the command line (via `-K`), which is insecure because any other user on the host may see it in
a process dump, or read from a file (specified via `-k`), which is recommended for production usages. All examples will
be shown with the `-K` variant with a fixed hexadecimal key of `aabbcc`, to allow for a quick copy&paste when playing
around. **Do not use in real world setups!**

Furthermore, each CocoonFs filesystem instance has a maximum supported block size, the filesystem "IO Block" size,
encoded in it, and the implementation will by default refuse to create or open a filesysten in case the underlying
hardware's block size happens to exceeds that. The reason is that the journalling mechanism relies on that, otherwise
power cuts or alike may lead to data loss. On Linux, the reported hardware IO Block size reported is typically
relatively large in practice (4kB, probably due to its page cache), whereas the default CocoonFs maximum IO Block size
is set to 512B. In practice, host filesystems, i.e. the filesystem the CocoonFs image file resides on, is likely to be
transactional itself, so data loss is no real concern. You may use the `-f` command line flag to override `cocoonfs`'
default behaviour and make it to ignore the block size constraint. All examples shown below will include that flag.

The examples demonstrate only basic usage. Especially for the filesystem creation commands, there's a plethora of
fine-tuning configuration parameters.

Run 
```
# cocoonfs help
```
for an overview on the available commands and
```
# cocoonfs help <COMMAND>
```
for the full details on a specific command.


## Filesystem creation
There are two mutually exclusive ways of creating a CocoonFs filesystem: a "regular" one which requires access to the
key at filesystem creation time, and another one which does not. The latter works by writing a special "filesystem
creation info header" to the image, and the actual filesystem formatting will then be conducted at first use, i.e. on
the first attempt to open it. It is intended to support confidential computing setups where the entity preparing the
image volume doesn't have access to the key.

In either case,
- a set of cryptographic algorithms and overall target security strength,
- a salt / id
- and the desired filesystem image size must get specified, the latter either explicitly on the command line, or
  implicitly through the (preexisting) target image file's bounds.

The set of cryptographic algorithms is supplied as a combination of a hash family like `sha2` and a block cipher,
e.g. `aes`. Hash algorithms will get selected automatically from the specified family for the various internal
filesystem purposes in accordance with the specified target security strenth. Likewise for the block cipher key size.

### Examples
**A word of caution: both filesystem creation commands will happily overwrite preexisting files, if any, there are no
safeguards!**


"Regular" filsystem creation of a 16MB image: `sha2` hash family, `aes` block cipher, target security strength of 128 bits,
a salt/id of hexadecimal `ddeeff` and a filesystem image size of 8MB:
```
# cocoonfs -i my-cocoonfs.img -f mkfs -H sha2 -C aes -t 128 -I 'ddeeff' -s 8M -K 'aabbcc'
```

Write a special ["filesystem creation info header"]{#mkfsinfo-header} instead, so that the filesystem will get created with the
configuration parameters specified at first use:
```
cocoonfs -i my-cocoonfs.img -f write-mkfs-info-header -H sha2 -C aes -t 128 -I 'ddeeff' -s 8M
```

## Writing to and reading from files in the CocoonFs image
The CocoonFs file namespace is very simple: it's flat, i.e. there is no notion of a directory hierarchy, and file
"names" are merely 32bit numbers starting from 6.

The source data to write may be either provided from a file on the host, or from `cocoonfs`' standard input if none is
specifed. Likewise, data read from a file in the CocoonFs image may be either written to a file on the host, or to
`cocoonfs`' standard output if none is specifed.

E.g. for writing "Hello world!" to file number 42:
```
# echo "Hello world!" | cocoonfs -i my-cocoonfs.img -f write-file -K 'aabbcc' 42
```
or
```
echo "Hello world!" > /tmp/hello-world-data.in
# cocoonfs -i my-cocoonfs.img -f write-file -K 'aabbcc' -i /tmp/hello-world-data.in 42
```

And for reading
```
# cocoonfs -i my-cocoonfs.img -f read-file -K 'aabbcc' 42
```
or
```
# cocoonfs -i my-cocoonfs.img -f read-file -K 'aabbcc' -o /tmp/hello-world-data.out 42
```

## Listing and deleting files
List all files stored in the CocoonFs image:
```
# cocoonfs -i my-cocoonfs.img -f list-files -K 'aabbcc'
```

And delete file number 42:
```
# cocoonfs -i my-cocoonfs.img -f remove-file -K 'aabbcc' 42
```

## Auxiliary filesystem metadata
In order to facilitate the integration with a wide variety of confidential computing environments and key retrieval
workflows (aka "remote attestation"), the CocoonFs format supports the storage of some auxiliary free-form metadata in
plain. An example would be a wrapped key to get unwrapped by a remote server upon a successful attestation of the
environment the filesystem is to get accessed. The auxiliary filesystem metadata is organized as a key-value store, with
the keys being [UUIDs](https://datatracker.ietf.org/doc/html/rfc4122). The UUIDs are expected to get allocated for a
specific workflow, or environment, or a combination thereof each, and the associated values' semantics are under the
authority of the respective UUID owner. The CocoonFs format itself does not put any constraints on whether a given
UUID may appear more than once in a filesystem's auxiliary filesystem metadata. It is up to the UUID owner to define
further restrictions, if desired.

It is possible to update the auxiliary metadata offline, i.e. without access to the key. However, reallocations are not
possible then, and the update will succeed only if a sufficient extra reserve capacity had been preallocated. This
constraint only applies to an already formatted filesystem, updates to the auxiliary filesystem metadata stored
alongside a [filesystem creation info header](#mkfsinfo-header) never require a key and are always possible (in fact,
the key will get ignored if provided).

### Adding an entry
For adding an entry with UUID `9ba370ab-4325-44eb-953e-32a04523bb1a` and contents "Hello world!":
```
# echo "Hello world" | cocoonfs -i /tmp/my-cocoonfs.img -f aux-fs-metadata edit -K 'aabbcc' add-entry 9ba370ab-4325-44eb-953e-32a04523bb1a

```
or
```
echo "Hello world!" > /tmp/hello-world-data.in
# cocoonfs -i my-cocoonfs.img -f aux-fs-metadata edit -K 'aabbcc' add-entry -i /tmp/hello-world-data.in 9ba370ab-4325-44eb-953e-32a04523bb1a
```

For conducting an offline update, omit the `-K` argument.

### Listing entries
For listing all auxiliary filesystem metadata entries, run
```
# cocoonfs -i my-cocoonfs.img -f aux-fs-metadata list-entries
```

### Reading an entry
For reading an auxiliary filesystem metadata entry's data:
```
# cocoonfs -i my-cocoonfs.img -f read-entry 9ba370ab-4325-44eb-953e-32a04523bb1a 0
```
or
```
# cocoonfs -i my-cocoonfs.img -f read-entry -o /tmp/hello-world-data.out 9ba370ab-4325-44eb-953e-32a04523bb1a 0
```

The trailing index argument, specified as "`0`" in the examples above, selects an entry among all with a matching
UUID. It may be omitted, in which case it defaults to `0`.

### Remove an entry
To remove an auxiliary filesystem metadata entry, run
```
# cocoonfs -i /tmp/my-cocoonfs.img -f aux-fs-metadata edit -K 'aabbcc' remove-entry 9ba370ab-4325-44eb-953e-32a04523bb1a 0

```

The trailing index argument, specified as "`0`" in the examples above, selects an entry among all with a matching
UUID. It may be omitted, in which case it defaults to `0`.

For conducting an offline update, omit the `-K` argument.

### Mananging the extra reserve capacity
As mentioned initially, reallocations are not possible without access to the filesystem key, and thus, offline updates
rely on the availability of some preallocated storage space, the "extra reserve capacity". Due to the transactional
manner in which offline updates are implemented for robustness against torn writes upon service interruptions, this
holds true even for attempts to write an update which would result in a net decrease of the total auxiliary filesystem
metadata size.

The extra reserve capacity is a property of the filesystem, and, once set, any subsequent auxiliary filesystem metadata
storage reallocation will consider it and allocate some excess space as appropriate. It can be in either of two states:
* Disabled -- No extra reserve at all will be allocated. Offline updates will not be possible, not even if resulting in
  a net decrease of total size.
* A size - Excess space will get allocated, sufficient for conducting the fail-safe transactional update operation, as
  well as for accomodating for a net increase of the total auxiliary filesystem metadata size up to that specified size.

The default initial extra reserve capacity property value may get overridden via the
`--aux-fs-metadata-extra-reserve-capacity` argument to either the `mkfs` or `write-mkfs-info-header` command. It may subsequently
get altered via e.g.
```
# cocoonfs -i my-cocoonfs.img -f aux-fs-metadata edit -K 'aabbcc' set-extra-reserve-capacity disabled
```
to disable it,
```
# cocoonfs -i my-cocoonfs.img -f aux-fs-metadata edit -K 'aabbcc' set-extra-reserve-capacity 0
```
to enable offline updates with no net increase of the total auxiliary filesystem metadata size or
```
# cocoonfs -i my-cocoonfs.img -f aux-fs-metadata edit -K 'aabbcc' set-extra-reserve-capacity 1K
```
to enable offline updates with a net increase of the total auxiliary filesystem metadata size up to 1KiB.

When run on a not yet formatted storage volume with a filesystem creation info header on it, the `-K` argument may be
omitted (it would in fact get ignored), and the effect is to set the property value to apply from the subsequent
filesystem creation operation.

When run on a formatted filesystem and the key is specified, as in the examples above, a reallocation will be made and
the new value takes effect immediately. Otherwise, if the key is omitted, only the property value will be updated, and
to get considered from a future reallocation operation only.
