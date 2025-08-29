# Cocoon TPM project - `cocoonfs-cli` crate

CLI program to work with CocoonFS image files -- create CocoonFS images and read, write, list and remove files in
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

Furthermore, each CocoonFS filesystem instance has a maximum supported block size, the filesystem "IO Block" size,
encoded in it, and the implementation will by default refuse to create or open a filesysten in case the underlying
hardware's block size happens to exceeds that. The reason is that the journalling mechanism relies on that, otherwise
power cuts or alike may lead to data loss. On Linux, the reported hardware IO Block size reported is typically
relatively large in practice (4kB, probably due to its page cache), whereas the default CocoonFS maximum IO Block size
is set to 512B. In practice, host filesystems, i.e. the filesystem the CocoonFS image file resides on, is likely to be
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
There are two mutually exclusive ways of creating a CocoonFS filesystem: a "regular" one which requires access to the
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

Write a special "filesystem creation info header" instead, so that the filesystem will get created with the
configuration parameters specified at first use:
```
cocoonfs -i my-cocoonfs.img -f write-mkfs-info-header -H sha2 -C aes -t 128 -I 'ddeeff' -s 8M
```

## Writing to and reading from files in the CocoonFS image
The CocoonFS file namespace is very simple: it's flat, i.e. there is no notion of a directory hierarchy, and file
"names" are merely 32bit numbers starting from 6.

The source data to write may be either provided from a file on the host, or from `cocoonfs`' standard input if none is
specifed. Likewise, data read from a file in the CocoonFS image may be either written to a file on the host, or to
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
List all files stored in the CocoonFS image:
```
# cocoonfs -i my-cocoonfs.img -f list-files -K 'aabbcc'
```

And delete file number 42:
```
# cocoonfs -i my-cocoonfs.img -f remove-file -K 'aabbcc' 42
```
