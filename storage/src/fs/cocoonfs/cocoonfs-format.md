``` {=html}
<style>
body { max-width: 72em !important; }
</style>
```
# CocoonFS format specification

Copyright 2023-2025 SUSE LLC

Licensed under CC BY-SA 4.0

## [Introduction]{#sec-introduction}
CocoonFS is a special purpose filesystem format designed for securely storing small items of highly sensitive data such
as, but not limited to, a software TPM's state and UEFI variables in a confidential Trusted Execution Environment (TEE)
setting.

In addition to its primary design focus on [strong security properties](#sec-introduction-security), the format
implemens support for some features of particular relevance to the intended use-case, such as support for [keyless
storage volume provisioning](#sec-introduction-online-mkfs) and robustness against service interruptions by means of a
[journal](#sec-introduction-journal).


### [Security properties]{#sec-introduction-security}
The most noteworthy features distinguishing CocoonFS from common existing Full Disk Encryption (FDE) solutions designed
primarily for mass storage deployments are:

* The use of fresh, random Initialization Vectors (IV) for each encryption operation.
* Authentication of the filesystem as a whole by means of a Merkle tree.
* The use of subkeys derived from a single (full-entropy) root key for each unique combination of filesystem entity and
  purpose as a means to confine wear-out.

Regarding cryptographic algorithms, the CocoonFS format supports the full set of block cipher and hash algorithms
specified by the TCG Algorithm Registry \[[TCGALG25](#bib-tcgalg25)\], with implementations explicitly being permitted
to support a subset thereof only.

All filesystem metadata is encrypted (and authenticated for that matter), even though some might be very well
predictable.

Details and rationale follow below.

#### Random IVs
Commonly used Full Disk Encryption (FDE) techniques operating exclusively at the block layer implement certain
trade-offs in order to maintain a reasonable level of efficiency on mass storage devices, but that comes at the cost of
sacrificing some cryptographic security properties not so important for data at rest. For a good discussion of the
encryption aspect refer to \[[KHATI16](#bib-khati16)\] and \[[FRUHWIRTH05](#bib-fruhwirth05)\], but in a nutshell it all
boils down to that *indistinguishability of encryptions* ("IND"), c.f. \[[GOLDREICH09](#bib-goldreich09)\] chapter 5,
cannot be achieved at full within a given fixed sector. That is, due to the fact that a sector's encryption tweak gets
derived exclusively from its location -- and is deterministic in particular -- it is possible to infer some relations
between two plaintexts encrypted successively to the same sector: e.g. whether the two plaintexts share a common prefix
(CBC-ESSIV) or some common data (XTS) at block cipher block granularity. Note that this is not much of a concern for
data at rest, because an adversary cannot observe two consecutive ciphertexts by definition.

The TEE threat model assumed for CocoonFS deployments is different in that respect though, in that an eavesdropper might
be capable of recording any individual storage write request issued from a TEE. Therefore a fresh, random IV is getting
generated for each encryption operation. Storing those random IVs for individual blocks would be too much overhead,
hence they are associated with logical filesystem entities -- either some metadata structure or a file -- instead. More
specifically, each entity is encrypted with a random IV in Cipher Block Chaining (CBC) mode. This does imply that
partial file updates are not possible, and neither are seeks for reading because of the choice of CBC mode. With the
kind of files anticipated to get typically stored on a CocoonFS target, i.e. small ones, the potential overhead incurred
with full file reads or writes is expected to be bearable though.

#### Authentication
Authentication serves two vital purposes:

* It provides assurance that any data read back from storage by an application is genuine, i.e. had previously been
  written out.
* Authentication of ciphertexts implements a measure against Chosen Ciphertext Attacks ("IND-CCA"),
  c.f. \[[GOLDREICH09](#bib-goldreich09)\] chapter 5.4.4.3.

For protecting application state, it is desirable that the units of authentication comprise individual files as a whole
at the very least: alternative approaches like the one taken by the Linux kernel's dm-integrity, which authenticates
individual device blocks, would potentially allow an adversary to revert selected parts of a file back to the state from
a previous write, i.e. to combine old with new contents.

Likewise, for IND-CCA security it is mandatory to authenticate the respective units of encryption ("messages" in common
crypto terminology) as a whole each -- that is, it is not sufficient to authenticate individual parts at e.g. device
block granularity independently from each other. With the units of encryption corresponding to the logical filesystem
entities, i.e. metadata or files, as described in the previous subsection, there are effectively two natural choices for
defining the units of authentication left:

* Authenticate each encryption entity individually and store an authentication tag inline to it, alongside the random
  IV.
* Implement a Merkle tree scheme for authenticating the filesystem as a whole.

Both alternatives have some pros and cons each. The authentication of individual filesystem entities is clearly more
efficient, in terms of storage space as well as computational work required (even though the inline storage of
authentication tags would inevitably introduce some significant padding waste to align allocations to an integral
multiple of the unit of allocation, which is 128B at least). A Merkle tree based scheme is more appealing from a
security property point of view, because it yields a single authentication tag binding the state of the CocoonFS
instance as a whole. This enables applications to distribute their state across multiple files while still being
guaranteed a globally coherent view. Note that in particular, that would allow for moving frequently written data, like
a software TPM's current time value, into a dedicated file, thereby avoiding the need to write out the complete, mostly
unchanged state upon each and every update. Furthermore, having a single root authentication digest for the whole
CocoonFS image available might perhaps serve as a basis for interesting future research projects in the area of rollback
protection protocols: any digest updates could get sent to and recorded at a trusted remote party (with the journal to
be introduced later providing a means to reliably recover from lost ACKs due to network failures).

It's expected that the storage backing CocoonFS deployments will typically be relatively small, i.e. that the height of
the Merkle tree will remain within affordable bounds. To get a rough idea on the numbers: five levels with an assumed
node size of 1kB and fanout of 16 would cover 128MB worth of data already. Moreover tree node caches can certainly help
with mitigating the overhead at the read side, as they can get organized such that especially the nodes at the upper
layers will have a good probability of cache residency.

With these considerations, the design choice made for CocoonFS is to accept the additional cost inherent to the Merkle
tree approach in favor of achieving better security guarantees.

As a minor technical detail, note that a few filesystem metadata items still need additional inline authentication tags
for preserving IND-CCA when e.g. finding the location of the authentication tree or reading the journal during
bootstrap, i.e. when opening the filesystem.

#### Key derivation
Some of the data stored on a CocoonFS instance will have low entropy, which might perhaps enable adversaries to acquire
plaintext-ciphertext pairs to conduct a cryptanalysis on. Examples would include e.g. the filesystem metadata
structures, but also certain application files' contents. In order to confine the effects of key wear-out, a unique
subkey is derived from a root key for each combination of filesystem entity and cryptographic purpose. The Key
Derivation Function (KDF) used for that is the `KDFa()` specified in \[[TCGTPM19A](#bib-tcgtpm19a)\].

The initially mentioned algorithm agility support, i.e. the possibility to use any of the algorithms from the TCG
Algorithm Registry \[[TCGALG25](#bib-tcgalg25)\] with CocoonFS, introduces a potential risk of downgrade attacks: by
overwriting algorithms with weak ones in the CocoonFS header, an adversary might perhaps be able to recover some subkey
or even the root key. In order to thwart such attacks, the externally supplied raw root key material, assumed to have
full entropy, is not taken as is, but first run through the `KDFa()` with a fixed hash algorithm, namely SHA-512, with
the other algorithms as found in the image header as additional input.


### Filesystem model
The filesystem model implemented by CocoonFS is a very limited one: there's no directory hierarchy and "file names" are
simply 32 bit integers, i.e. inode numbers.

It is expected that some inode numbers or ranges thereof get statically assigned to a specific application purpose. For
example, when storing a software TPM's state, it would be natural to reserve the ranges 0x01000000-0x01ffffff for the
storage of NV indices and 0x81000000-0x81ffffff for persistent objects, c.f. \[[TCGTPM19B](#bib-tcgtpm19b)\].

Note that for the anticipated CocoonFS usage scenarios, i.e. the storage of core TEE state, it will likely always be
possible to make such static assignments at development time and thus, it is certainly desirable to avoid the overhead
of updating directory metadata structures.

### [Journal]{#sec-introduction-journal}
For robustness against service interruptions, e.g. power cuts, crashes and alike, CocoonFS implements a journal.

In fact, it is not so much of a journal in the traditional sense as in "a journal with multiple update records": the
CocoonFS journal's capacity is limited to tracking a single pending transaction at a time, where that single transaction
can comprise an arbitrary number of accumulated filesystem operations.

Unlike it's the case with other journal implementations, there's no dedicated, preallocated journal area except for a
small (a single IO Block) entry structure at a fixed location, the *journal log head*, potentially linking to further,
dynamically allocated parts describing the pending transaction.

That journal log head is supposed to get written last, after the remainder of the journal has been setup. Once in place,
the filesystem update is considered effective and success may get reported back to the issuing application at this point
already.

Note that the journalling functionality might provide a convenient basis for implementing a rollback protection protocol
robust against network failures.

For example, upon update, the filesystem implementation could

1. Setup the journal. At this point it is possible to transition to the new state or to revert back.
2. Send the new authentication root digest to the remote trusted party.
4. Wait for an ACK reply. In the common case that an ACK is received, apply the journal. If no ACK is being received,
   retry to reach the remote party until it answers.

For handling any power cuts encountered after the new root digest has been sent, but before a reply has been received
back, make the filesystem opening code to query the remote trusted party for the latest root authentication digest at
filesystem opening time, depending on the answer either apply or cancel the pending journal.

### [Confidentiality of allocations and block trimming]{#sec-allocations-confidentiality}
Ideally it should not be possible for an adversary to infer the allocation status of any blocks at any time, because
that would e.g. allow for fingerprinting the TEE's workload.

The metadata tracking the allocations, i.e. the [allocation bitmap](#sec-allocation-bitmap), is encrypted, but in the
assumed TEE threat model of an active adversary able to eavesdrop on IO requests, it is difficult to specify clear,
well-defined security semantics with respect to the confidentiality of the overall allocations state: for example,
whenever a given block is read or written, an adversary observing the IO may readily infer it's allocated at that point
in time.

For that reason, CocoonFS does not define any security guarantees regarding the confidentiality of allocations with
respect to adversaries able to eavesdrop or even alter IO communication.

As a side note: this relaxation is a prerequisite for the support of a dynamically allocated journal: the blocks used
temporarily for the journal can be in any state, therefore their contents cannot get authenticated reliably. More
generally, unallocated block's contents cannot get considered as input for the authentication, only the fact that they
are unallocated can, but this implies that a given block's authentication tag returns to a previous value when
deallocated, something which would otherwise have been highly unlikely.

CocoonFS does however provide optional confidentiality of allocations in the "data at rest model". If enabled, certain
additional measures with some computational overhead need to get taken -- most notably a
[reencryption](#sec-journal-staging-copy-disguise) of data copies in the journal in order to prevent the identification
of journal blocks by matching them to duplicates.

Implementations may issue trim commands for deallocated blocks to the underlying storage device. Note however that
trimming is mutually exclusive with the confidentiality of allocations, because a trimmed block is usually recognizable
as such.

### [Online filesystem creation support]{#sec-introduction-online-mkfs}
In some use-cases, e.g. TEEs running in a public cloud, it might be desirable to create the filesystem from within the
TEE itself upon first use: the initial filesystem creation requires access to the root key, and, as the TEE would need
that anyway, such a setup scheme would allow for limiting the trust boundary to the bare minimum.

However, a TEE should certainly not start to randomly create CocoonFS instances on any attached volumes whose formats it
doesn't recognize and some sort of storage volume tagging mechanism is due. The CocoonFS format implements this by means
of a special [filesystem creation header](#sec-mkfsinfo-header) marking the containing volume as intended for formatting
with a CocoonFS instance at first use in the first place, and specifying all the core configuration parameters required
for the filesystem creation.

**Attention**: the [filesystem creation header](#sec-mkfsinfo-header) is not authenticated at all, and thus, to thwart
downgrade attacks on the set of cryptographic algorithms, these **must** get authenticated/attested/validated by some
other, unspecified means. If there's any potential for root key reuse, then the filesystem salt **must** get
authenticated as well.

The initial filesystem creation process involves a replacement of the [filesystem creation header](#sec-mkfsinfo-header)
with the [regular filesystem header](#sec-filesystem-header) at some point. For robustness against service interruptions
encountered during this final write operation, a backup copy of the [filesystem creation header](#sec-mkfsinfo-header)
is to be written at a specific location on storage determined exclusively from its dimensions beforehand. In case no
valid (integrity protected) [image header](#sec-image-header) of either type is found at the beginning of the storage
when attempting to open a filesystem, i.e. following a service interruption, the implementation is supposed to check for
the presence of the backup [filesystem creation header](#sec-mkfsinfo-header) and restart the filesystem creation as
appropriate.

## Fundamental structures and encodings
The core CocoonFS metadata structures are:

* The [image header](#sec-image-header) defining filesystem properties, split into an
  [immutable](#sec-static-image-header) and a [mutable](#sec-mutable-image-header) part. The immutable part contains all
  static configuration parameters, the immutable part the changing values such as the authentication tree root digest,
  the filesystem image size etc.
* The [authentication tree](#sec-auth-tree).
* The [allocation bitmap](#sec-allocation-bitmap) tracking the allocation status of each *Allocation Block* in the
  filesystem image.
* The [inode index](#sec-inode-index), organized as a B+-tree.
* The [journal](#sec-journal).

Inodes 0 to 5 (inclusive) are reserved for CocoonFS internal use. The [authentication tree](#sec-auth-tree), the
[allocation bitmap](#sec-allocation-bitmap) and the [inode index](#sec-inode-index) root have entries in the inode index
and are assigned inode numbers 1, 2 and 3 respectively. The [journal log](#sec-journal) has inode number 5 associated
with it, but there's no explicit entry for it in the inode index -- the number is used only for key derivation subject
purposes.

For completeness in this context: inode number 0 is reserved for a special "no inode" value, inode number 4 is currently
not allocated and reserved. Note that the minimum inode index B+-tree node fill-level is such that inodes 1 to 4 will
always be found in the leftmost leaf, which is referred to as the [*inode index entry leaf
node*](#def-inode-index-entry-leaf-node). The location of the inode index entry leaf node is referenced from the
[mutable image header](#sec-mutable-image-header) and enables discovering all the other metadata structures at
filesystem opening time.

An [*extent*]{#def-extent} is a **non-empty**, physically contiguous range on storage. Any inode, except for the special
inode index root node inode, stores its data in one or more extents.

The term [*block*]{#def-block} is used to denote an extent which is a power of two in length and whose length is
implicit from the context. Block boundaries on storage are not necessarily aligned to the block size in the general
case, any alignment requirements on extents or blocks are stated explicitly where they apply.

The unit of allocations is an [*Allocation Block*]{#def-allocation-block}, a power of two multiple of 128B, specified as
a configuration parameter in the static image header. The [allocation bitmap](#sec-allocation-bitmap) has one bit entry
associated with each possible Allocation Block in the filesystem image: if set, the corresponding Allocation Block is
allocated, otherwise it's free.

Unless otherwise noted, all locations on storage are specified in units of Allocation Blocks. The maximum supported
filesystem image size is $2^{64} - 1$ rounded down to the Allocation Block size.

An [*IO Block*]{#def-io-block} is a power of two multiple of the Allocation Block size, specified as a filesystem
parameter in the static image header and defining an upper bound on the supported backing device's IO granularity. More
specifically, it is assumed that a write to an aligned IO Block doesn't affect the contents of any other IO
Block. Implementations must reject to open a filesystem if the backing storage device supports only larger IO sizes than
the IO Block size recorded in the static image header.

The filesystem image size must always be a multiple of the IO Block size. Note that this effectively limits the maximum
supported image size to $2^{64} - 1$ rounded down to the IO Block size.

An [*Authentication Tree Data Block*]{#def-auth-tree-data-block} is a power of two multiple of the Allocation Block
size, specified as a filesystem parameter in the static image header and defining the unit of authentication, i.e the
fan-out factor from the [authentication tree](#sec-auth-tree) leafs' entries.

All of the authentication tree's extents' boundaries must be aligned to the larger of the IO Block and the
Authentication Tree Data Block size.

All of the [allocation bitmap's](#sec-allocation-bitmap) extents' boundaries must be aligned to the Authentication Tree
Data Block size, as is required for bootstrapping the authentication at filesystem opening time: in general an
Authentication Tree Data Block's individual Allocation Blocks' respective allocation status must be known each for
[computing its authentication digest](#sec-auth-tree-data-block-digest), but with the aligned allocation bitmap file
extents all overlapping Authentication Tree Data Blocks' Allocation Blocks are known a priori to be allocated.

### Storage location encodings
#### [Encoded extent pointer]{#sec-enc-extent-ptr}
An *encoded extent pointer* is a packed 64 bit encoding format for specifying the location and type of an
[extent](#def-extent) of up to 64 [Allocation Blocks](#def-allocation-block).

The type of an extent referenced from an encoded extent pointer is either "direct" or "indirect". A direct extent
contains payload data, an indirect one (the beginning of) an [encoded extent list](#sec-enc-extents-list) specifying the
extents containing the actual payload data. Indirect extents are used if the payload data either exceeds 64 Allocation
Blocks or spans multiple extents and can be referenced only from entries in the inode index.

An encoded extent pointer is formed as follows:

* Shift the referenced extent's beginning on storage in units of Allocation Blocks represented as a 64 bit integer to
  the left by 7 bits.
* Subtract one from the extent length in units of Allocation Blocks represented as a 64 bit integer and shift it to the
  left by 1 bit.
* Or the two values together, set the least significant bit if the referenced extent's type is "indirect", encode the
  resulting integer in little-endian format.

The value of all-zeros denotes a special "NIL" value -- as the static image header is located at the filesystem image's
beginning, no extent can ever start at position 0.

Note that with a maximum supported filesystem image size of $2^{64} - 1$ rounded down to the Allocation Block size, and
a minimum Allocation Block size of 128B, any Allocation Block index always has its upper 7 bits clear, so the shift in
the first step wouldn't shift non-zero bits out.

#### [Encoded block pointer]{#sec-enc-block-ptr}
An *encoded block pointer* is a packed encoding format for specifying the location a [block](#def-block), i.e. some
extent whose length is a fixed power of two implicit from the context.

An encoded block pointer is formed by shifting the block's beginning on storage in units of Allocation Blocks
represented as a 64 bit integer to the left by 7 bits. The lower 7 bits are reserved for future use.

The value of all-zeros denotes a special "NIL" value -- as the static image header is located at the filesystem image's
beginning, no block can ever start at position 0.

#### [Encoded extents list]{#sec-enc-extents-list}
An *encoded extents list* specifies the location of one or more [extents](#def-extent).

The extents lists is encoded as a sequence of (beginning, length) pairs, one for each extent.

An extent's beginning is specified in terms of the difference relative to the previous extent's end, if any, or zero for
the first entry, in units of [Allocation Blocks](#def-allocation-block) and represented in two's complement modulo
$2^{64}$, encoded in signed LEB128 format. An extent's length is specified in units of Allocation Blocks and encoded in
unsigned LEB128 format. It must not be zero.

The encoded list is terminated by two zero bytes.

### [Authentication contexts]{#sec-auth-context}
Any data digested for authentication gets extended by an *authentication context* for the purpose of the digesting
operation. The authentication context uniquely encodes the type and format of the authenticated data. Its exact format
depends on the authenticated subject, but it always ends with one of the [*authentication subject
identifiers*]{#def-auth-subject-id} defined in the table below. An authentication context's subject identifier uniquely
identifies the format and semantics of its remainder, which in turn binds the format and semantics of the authenticated
data.

+---------------------------------------------------+-------+----------------------------------------------------------+
|Name                                               | Value |Authentication subject description                        |
+===================================================+=======+==========================================================+
|`AUTH_SUBJECT_ID_IMAGE_CONTEXT`                    |1      |Collection of filesystem configuration parameters         |
|                                                   |       |describing the layout as well as the locations of certain |
|                                                   |       |entities needed for bootstrapping at filesystem opening   |
|                                                   |       |time. The [image context                                  |
|                                                   |       |digest](#sec-auth-tree-root-digest) gets in turn digested |
|                                                   |       |into the authentication tree root digest.                 |
+---------------------------------------------------+-------+----------------------------------------------------------+
|`AUTH_SUBJECT_ID_AUTH_TREE_ROOT_NODE`              |2      |The [authentication tree root                             |
|                                                   |       |node](#sec-auth-tree-root-digest).                        |
+---------------------------------------------------+-------+----------------------------------------------------------+
|`AUTH_SUBJECT_ID_AUTH_TREE_DESCENDANT_NODE`        |3      |[Non-root authentication tree                             |
|                                                   |       |node](#sec-auth-tree-descendant-node-digest).             |
+---------------------------------------------------+-------+----------------------------------------------------------+
|`AUTH_SUBJECT_ID_AUTH_TREE_DATA_BLOCK`             |4      |[Authentication tree data                                 |
|                                                   |       |block](#sec-auth-tree-data-block-digest).                 |
+---------------------------------------------------+-------+----------------------------------------------------------+
|`AUTH_SUBJECT_ID_ENCRYPTION_ENTITY_CHAINED_EXTENTS`|5      |Extent in a sequence of [encrypted chained                |
|                                                   |       |extents](#sec-encryption-entity-chained-extents).         |
+---------------------------------------------------+-------+----------------------------------------------------------+
|`AUTH_SUBJECT_ID_INODE_INDEX_NODE`                 |6      |A node in the inode index tree. Used only for             |
|                                                   |       |[authenticating the contents of the inode index entry leaf|
|                                                   |       |node](#sec-inode-index-entry-leaf-node-preauth-digest).   |
+---------------------------------------------------+-------+----------------------------------------------------------+
|`AUTH_SUBJECT_ID_JOURNAL_LOG_FIELD`                |7      |A field in the [journal log](#sec-journal).               |
+---------------------------------------------------+-------+----------------------------------------------------------+

### Encryption entity formats
There are three different encryption entity formats defined:
* one for encrypted [blocks](#def-block), where it is assumed that the length of the encrypted payload is implicit from
  the context,
* one for a sequence of encrypted extents, where the locations of all [extents](#def-extent) the sequence are determined
  by some means external to the encrypted entity and
* one for a linked list of extents, where only the head extent's locations is determined by some external means while
  the tail is to be found by traversing the linked list.

For example, the block encryption format is used for nodes in the inode index B+-tree, the encrypted extents for inode
data, and chained encrypted extents for storing [inode extents lists](#sec-enc-extents-list) as well as the journal log.

#### [Encrypted block]{#sec-encryption-entity-block}
An encrypted [block's](#def-block) payload length is assumed to be known a priori from the context.

The format is stored as follows:

1. The IV for the CBC block cipher chaining mode.
2. Randomized padding to align the remainder of the block's length to a multiple of the block cipher block length. Note
   that the padding is empty for all possibly supported block cipher algorithms currently defined in the [TCG Algorithm
   Registry](#bib-tcgalg25).
3. An integral multiple of block cipher blocks storing the result of encrypting the fixed-length payload in CBC block
   cipher chaining mode.
4. An integral multiple of remainder block cipher blocks extending up to the encryption entity block's end and filled
   with random data.

As the payload length is assumed to be fixed and implicit from the context, it is unspecified how to pad the encrypted
payload to align with the block cipher block length. It is also unspecified how the remainder of the encrypted entity
block is filled with random data. Implementations might e.g. simply continue the CBC encryption on a sequence of zeros,
or they make invoke a cryptographic random number generator (CSPRNG).

#### [Encrypted extents]{#sec-encryption-entity-extents}
The locations of all extents in the sequence is assumed to be determined by some means external to the encrypted entity,
the encrypted payload may be of any length, zero included.

The IV is stored at the beginning of the first extent. Randomized padding is inserted in any extent to align the
remainder of the extents' lengths to a multiple of the block cipher block size each -- after the IV for the first
extent, at the extents' beginnings for any subsequent extent. Note that the padding is empty for all possibly supported
block cipher algorithms currently defined in the [TCG Algorithm Registry](#bib-tcgalg25). The remainders of all extents
are concatenated to collectively form the ciphertext. The ciphertext is the result of encrypting the payload, amended by
a PKCS#7 padding and an integral multiple of zero-filled block cipher blocks as appropriate, in CBC block cipher
chaining mode.

#### [Encrypted chained extents]{#sec-encryption-entity-chained-extents}
Only the location of the first extent in a sequence of chained extents is assumed to be determined by some means
external to the encrypted entity: the chained extents form a singly linked list with the pointers to the respective next
extent being part of the encrypted plaintexts each.

Encrypted chained extents come in two flavors: with and without inline authentication. The variant with inline
authentication is used for implementing IND-CCA security for certain filesystem structures at filesystem opening time
before the full Merkle tree based authentication has been bootstrapped.

The first extent may store some optional plaintext header at its beginning, like e.g. a magic for the journal log head,
followed by the mandatory IV. For the inline authenticated variant an authentication tag is stored in each extent in the
chain: after the IV for the first extent, at the extents' beginnings for any subsequent continuation extent. Randomized
padding is then inserted at the current position in each extent in order to align its remainder to an integral multiple
of the block cipher block size.

The (aligned) remainder of each extent constitutes its ciphertext. The ciphertext is the result of encrypting the
plaintext associated with an extent in CBC mode, with the IV being the output IV from the previous extent's CBC
encryption, if any, or the IV stored inline to the first extent otherwise. The extents' plaintexts are formed by
prepending an [encoded extent pointer](#sec-enc-extent-ptr) with its "indirect" bit clear and linking to the next extent
in the chain, if any, or set to NIL if not, to a chunk of payload data from the encrypted entity. Chunks of entity
payload data are consumed greedily, that is, each but the last extent's capacity is exhausted in full. A PKCS#7 padding
is appended to the last extent's plaintext, followed by an integral multiple of zero-filled block cipher blocks as
appropriate.

For the inline-authenticated variant, the extents' authentication tags are computed as HMACs over the following data:

1. The extent's stored contents, with the authentication tag replaced by all-zeros for the first extent, or by the
   previous extent's authentication tag for any subsequent continuation extent.
2. An additional [authentication context](#sec-auth-context) constructed as follows:
   1. For a continuation extent only: the IV used for the extent's CBC encryption, i.e. the IV output from the previous
      extent's encryption.
   2. Possibly empty authenticated associated data common to all extents.
   3. A single byte set to 0 for the first extent, or to 1 for any subsequent continuation extent.
   4. An authentication context format version identifier byte of constant 0.
   5. An authentication context subject identifier byte of constant
      [`AUTH_SUBJECT_ID_ENCRYPTION_ENTITY_CHAINED_EXTENTS`](#def-auth-subject-id) identifying the authenticated subject.

The security strength of authenticating the individual extents with a HMAC is that of the underlying hash's preimage
resistance, i.e. the digest size in bits usually. Note however that because intermediate authentication tags in the
chain are public, including the previous one in the digest for the next extent in the chain provides authenticity for
the chain as a whole only at the underlying hash's collision resistance, which is at most half the underlying hash's
digest length. In fact the inclusion of the previous tags is not needed for correctness or soundness at all, but
implements an integrity protection measure for the sequence of chained extents as a whole at little additional cost,
which is good to have from a robustness perspective, especially for the journal log.

### [Image header]{#sec-image-header}
The CocoonFS format defines two mutually exclusive header types to be placed at the containing storage volume's
beginning:

- In the regular case, after the filesystem has been created on storage and is operational, the [regular CocoonFS
  filesystem header](#sec-filesystem-header) is stored at that location.
- Alternatively, to drive [online filesystem creation](#sec-introduction-online-mkfs) upon first use, a [filesystem
  creation info header](#sec-mkfsinfo-header) may be placed there. It is expected that implementations will conduct the
  filesystem creation upon encountering such one, eventually replacing the header with a [regular CocoonFS
  filesystem header](#sec-filesystem-header) in the course.

Both header types are protected by a checksum each. If no valid header of either type passing checksum verification is
found at the storage's beginning when attempting to open a filesystem, implementations are expected to check for the
presence of a filesystem creation info header [backup copy](#def-mkfsinfo-backup-header) at a specific location
determined exclusively from the backing storage volume's dimensions, and proceed with the online filesystem creation if
one is found.

#### [Regular CocoonFS filesystem header]{#sec-filesystem-header}
The regular CocoonFS filesystem image header is split into two parts: a [static](#sec-static-image-header) and a
[mutable](#sec-mutable-image-header) one.  The static image header is located at the beginning of the image, padded to
an integral multiple of the [IO Block](#def-io-block) size so that no neighboring writes will ever alter its
contents. This is important, as the configuration found in the static image header is needed for determining the
filesystem layout and locating the fixed position of the journal log head.

The mutable header is located past the static image header's padding, and changes to it are tracked through the journal,
just as is the case for any update. It contains changing values such as the filesystem image size or the authentication
tree root hash.

##### [Static image header]{#sec-static-image-header}
The static image header starts at offset zero, its format is:

+----------------+----------------------------------------------------------------------------------+
|Length in bytes |Description                                                                       |
+================+==================================================================================+
|8               |Magic string `'COCOONFS'` (without a terminating zero byte).                      |
+----------------+----------------------------------------------------------------------------------+
|1               |The filesystem format version. Fixed to 0.                                        |
+----------------+----------------------------------------------------------------------------------+
|20              |The set of filesystem image layout parameters, c.f. further below.                |
+----------------+----------------------------------------------------------------------------------+
|1               |The salt length.                                                                  |
+----------------+----------------------------------------------------------------------------------+
|variable        |The salt.                                                                         |
+----------------+----------------------------------------------------------------------------------+
|4               |Cyclic redundancy checksum over the header.                                       |
+----------------+----------------------------------------------------------------------------------+
|4               |Cyclic redundancy checksum over the header with any two neighboring bits swapped. |
+----------------+----------------------------------------------------------------------------------+

After the static image header, some padding is inserted up to the next [IO Block](#def-io-block) alignment
boundary. None of the IO Blocks overlapping with the static image header, including that padding, may ever get written
to.

The set of filesystem configuration parameters, referred to as the [*image layout*]{#def-image-layout}, is encoded as
follows:

+-------+-----------------------------------------------------+--------------------------------------------------------+
|Encoded|Name                                                 |Description                                             |
|length |                                                     |                                                        |
|  in   |                                                     |                                                        |
| bytes |                                                     |                                                        |
+=======+=====================================================+========================================================+
| 1     |`allocation_block_size_128b_log2`                    |Size of an [Allocation Block](#def-allocation-block),   |
|       |                                                     |specified as the base-2 logarithm of the size in units  |
|       |                                                     |of 128B.                                                |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 1     |`io_block_allocation_blocks_log2`                    |Size of an [IO Block](#def-io-block), specified as the  |
|       |                                                     |base-2 logarithm in units of Allocation Blocks.         |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 1     |`auth_tree_node_io_blocks_log2`                      |Size of an [authentication tree node](#sec-auth-tree),  |
|       |                                                     |specified as the base-2 logarithm in units of IO Blocks.|
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 1     |`auth_tree_data_block_allocation_blocks_log2`        |Size of an [Authentication Tree Data                    |
|       |                                                     |Block](#def-auth-tree-data-block), specified as the     |
|       |                                                     |base-2 logarithm in units of Allocation Blocks. Must be |
|       |                                                     |<= 6.                                                   |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 1     |`allocation_bitmap_file_block_allocation_blocks_log2`|Size of an [allocation bitmap file                      |
|       |                                                     |block](#sec-allocation-bitmap), specified as the base-2 |
|       |                                                     |logarithm in units of Allocation blocks.                |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 1     |`index_tree_node_allocation_blocks_log2`             |Size of an [inode index](#sec-inode-index) B+-tree node,|
|       |                                                     |specified as the base-2 logarithm in units of Allocation|
|       |                                                     |blocks. Must be <= 64.                                  |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 2     |`auth_tree_node_hash_alg`                            |[TCG algorithm identifier](#bib-tcgalg25) of the hash   |
|       |                                                     |algorithm to be used for [digesting the descendant,     |
|       |                                                     |non-root nodes of the authentication                    |
|       |                                                     |tree](#sec-auth-tree-descendant-node-digest), referred  |
|       |                                                     |to as the "authentication tree node hash                |
|       |                                                     |algorithm". Encoded in big-endian format.               |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 2     |`auth_tree_data_hmac_hash_alg`                       |[TCG algorithm identifier](#bib-tcgalg25) of the hash   |
|       |                                                     |algorithm to be used for [digesting Authentication Tree |
|       |                                                     |Data Blocks](#sec-auth-tree-data-block-digest), referred|
|       |                                                     |to as the "authentication tree data hash                |
|       |                                                     |algorithm". Encoded in big-endian format.               |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 2     |`auth_tree_root_hmac_hash_alg`                       |[TCG algorithm identifier](#bib-tcgalg25) of the hash   |
|       |                                                     |algorithm to be used for [digesting the root node of the|
|       |                                                     |authentication tree](#sec-auth-tree-root-digest), the   |
|       |                                                     |"authentication tree root hash algorithm". Encoded in   |
|       |                                                     |big-endian format.                                      |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 2     |`preauth_cca_protection_hmac_hash_alg`               |[TCG algorithm identifier](#bib-tcgalg25) of the hash   |
|       |                                                     |algorithm to be used for the inline authentication of   |
|       |                                                     |various metadata items for maintaining IND-CCA during   |
|       |                                                     |bootstrapping, referred to as the "preauthentication CCA|
|       |                                                     |protection hash algorithm". Encoded in big-endian       |
|       |                                                     |format.                                                 |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 2     |`kdf_hash_alg`                                       |[TCG algorithm identifier](#bib-tcgalg25) of the hash   |
|       |                                                     |algorithm to be used for [deriving                      |
|       |                                                     |subkeys](#sec-key-derivation) by means of the TCG       |
|       |                                                     |`KDFa()`, referred to as the "key derivation hash       |
|       |                                                     |algorithm".                                             |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 4     |`block_cipher_alg`                                   |[TCG algorithm identifier](#bib-tcgalg25) and key size  |
|       |                                                     |of the block cipher algorithm used for any              |
|       |                                                     |encryption. Encoded as a pair of two 16 bit integers in |
|       |                                                     |big-endian format each.                                 |
+-------+-----------------------------------------------------+--------------------------------------------------------+

###### [Cyclic redundancy checksum (CRC) computation]{#sec-crc}
The static image header is integrity protected by a pair two CRC-32s: one over the plain header data from the magic to
the salt, both inclusive, and another one over the same data but with any two neighboring bits swapped.

The CRC polynomial used in either case is the standard CRC-32 one, with a corresponding 32 bit integer representation of
`0x04c11db71`, where the arithmetically most significant bit specifies the coefficient to the term of degree $31$, and
the least signigicant bit the constant term. A string of $32$ $1$-bits is prepended to the data before the CRC
computation starts. Successive bytes in the data correspond to terms of decreasing degree in the to be reduced data
polynomial, and within each byte, bits of decreasing arithmetic significance correspond to terms of increasing
polynomial degree. The final residual polynomial's coefficient are inverted and serialized with the same association
between polynomial terms and bits on storage as just described for the data.

The distribution of the CRC algorithm output over uniformly distributed data is again uniform, so in this idealized case
the probability of not detecting random errors with a single CRC-32 is $1:2^{32}$. One of the checksum's primary
purposes is to detect incomplete writes issued from an interrupted filesystem creation operation -- the only point in
time the static image header is getting actively written to. A chance of $1:2^{32}$ for missing header corruptions may
well be considered too unreliable, and a 64 bit checksum should be used instead. The most straightforward solution would
be to use a CRC-64 variant. However, in practice, this would double the size of a CRC implementation's internal lookup
tables, which is undesirable. So a different approach is taken instead: a 64 bit checksum is formed by combining one
CRC-32 over the header's data with another over the same data, but with any two neighboring bits swapped. Because the
CRC-32 polynomial is irreducible -- hence the ring of its residue classes is a field, this is equivalent to computing
two independent CRC-32 values over the bits at odd and even positions in the input data each. Therefore, the probability
of missing uniformly random corruptions is $1:2^{64}$.

The well-known feature of CRC-64 that burst errors of length up to 64 bits are detected reliably also applies to this
method of combining the two CRC-32 checksums. To see this, consider the polynomial ring $\mathbb{F}_2[X]$ with
coefficients in the binary field $\mathbb{F}_2$. Denote the CRC polynomial in this ring by $\mathcal{c}$. The ability to
detect burst errors up to a length of 64 bits translates to requiring that the only polynomial of degree less than 64
with its terms of odd degree all zero and a residue $\mathrm{mod}\mathcal{c}$ of zero is the zero polynomial. Note that
$\mathrm{char}(\mathbb{F}_2)=2$, and $\phi: p\mapsto p^2$ is a ring endomorphism on $\mathbb{F}_2[X]$. In particular
$\phi(X)=X^2$. The image of $\phi$ is exactly the set of polynomials with their terms of odd degree all zero. Observe
that $\phi(\mathcal{c})=\mathcal{c}^2$ yields such a polynomial with a residue $\mathrm{mod}\mathcal{c}$ of $0$. It has
degree $64$ though, and it remains to be shown that this is the polynomial of least degree with these
properties. Consider the composition of maps $\psi\circ\phi$, where $\psi$ denotes the canonical map
$\mathbb{F}_2[X]\rightarrow \mathbb{F}_2[X]/(\mathcal{c})$ into the residue class ring.  The
$\mathrm{kern}(\psi\circ\phi)$ is an ideal in $\mathbb{F}_2[X]$, and is prinicipal, because $\mathbb{F}_2[X]$ is a
principal ideal ring. That is, $\mathrm{kern}(\psi\circ\phi)=(\bar{\mathcal{c}})$ for some
$\bar{\mathcal{c}}\in\mathbb{F}_2[X]$, and $\phi(\bar{\mathcal{c}})$ is a polynomial of minimum degree in
$\mathrm{kern}(\psi)$ with its terms of odd degree all zero. By what has been said above, it is already known that
$\mathcal{c}\in\mathrm{kern}(\psi\circ\phi)=(\bar{\mathcal{c}})$. Finally, because $\mathcal{c}$ is irreducible (and
$\mathbb{F}_2$'s only unit is $1$), it follows that $\mathcal{\bar{c}}=\mathcal{c}$.


##### [Mutable image header]{#sec-mutable-image-header}
The mutable image header is located at the first [IO Block](#def-io-block) aligned boundary following the static image
header. It gets updated through the general journalling mechanics, hence it may be in an inconsistent state at
filesystem opening time.

The mutable image header's format is:

+---------------------------------------+------------------------------------------------------------------------------+
|Length                                 |Description                                                                   |
+=======================================+==============================================================================+
|Digest length produced by              |The [authentication tree root HMAC digest](#sec-auth-tree-root-digest).       |
|`auth_tree_root_hmac_hash_alg`.        |                                                                              |
+---------------------------------------+------------------------------------------------------------------------------+
|Digest length produced by              |[HMAC digest over the inode index entry leaf                                  |
|`preauth_cca_protection_hmac_hash_alg`.|node](#sec-inode-index-entry-leaf-node-preauth-digest), used for maintaining  |
|                                       |IND-CCA security when first decrypting the node at filesystem opening time.   |
+---------------------------------------+------------------------------------------------------------------------------+
|8B                                     |[Encoded block pointer](#sec-enc-block-ptr) to the [inode index entry leaf    |
|                                       |node](#def-inode-index-entry-leaf-node).                                      |
+---------------------------------------+------------------------------------------------------------------------------+
|8B                                     |The filesystem image size in units of [Allocation                             |
|                                       |Blocks](#def-allocation-block), encoded as a 64 bit integer in little-endian  |
|                                       |format.                                                                       |
+---------------------------------------+------------------------------------------------------------------------------+
|variable                               |Padding to align the mutable image header's length to a multiple of the       |
|                                       |[Allocation Block](#def-allocation-block) size.                               |
+---------------------------------------+------------------------------------------------------------------------------+

#### [Filesystem creation info header]{#sec-mkfsinfo-header}
As discussed in the introductionary section about [online filesystem creation support](#sec-introduction-online-mkfs),
parties not in possession of the root key may mark a storage volume for formatting with a CocoonFS instance upon first
use by writing a special filesystem creation info header to its beginning. This header provides all the information
required for the actual filesystem creation and is of the following format:

+----------------+------------------------------------------------------------------------------------+
|Length in bytes |Description                                                                         |
+================+====================================================================================+
|8               |Magic string `'CCFSMKFS'` (without a terminating zero byte).                        |
+----------------+------------------------------------------------------------------------------------+
|1               |The filesystem creation info header format version. Fixed to 0.                     |
+----------------+------------------------------------------------------------------------------------+
|20              |The set of filesystem image layout parameters, encoded in the same                  |
|                |[format](#def-image-layout) as for the regular filesystem header's static part.     |
+----------------+------------------------------------------------------------------------------------+
|8               |The desired filesystem image size in units of [Allocation                           |
|                |Blocks](#def-allocation-block), encoded as a 64 bit integer in little-endian format.|
+----------------+------------------------------------------------------------------------------------+
|1               |The salt length.                                                                    |
+----------------+------------------------------------------------------------------------------------+
|variable        |The salt.                                                                           |
+----------------+------------------------------------------------------------------------------------+
|4               |Cyclic redundancy checksum over the header.                                         |
+----------------+------------------------------------------------------------------------------------+
|4               |Cyclic redundancy checksum over the header with any two neighboring bits swapped.   |
+----------------+------------------------------------------------------------------------------------+

The filesystem creation info header is protected by a pair of two CRC-32s: one over the plain header data from the magic
to the salt, both inclusive, and another one over the same data but with any two neighboring bits swapped, just in line
with the regular filesystem header's [checksum computation](#sec-crc).

Upon encountering such a filesystem creation header passing the checksum verification at the storage volume's beginning
when attempting to open a filesystem, implementations are supposed to conduct the filesystem creation.

The filesystem creation process inevitably involves a replacement of the filesystem creation info header at the
storage's beginning with the [regular CocoonFS image header](#sec-filesystem-header) at some point. For robustness
against service interruptions encountered during that write, a [backup copy]{#def-mkfsinfo-backup-header} of the former
is made at a specific location on storage beforehand. The location is determined exlusively from the storage volume's
dimensions as follows: find the largest possible power of two not less than $4\cdot 128\textrm{B}$ such that the storage
volume accomodates at least $16$ units of that size and place the backup filesystem creation info header copy at the
beginning of the last such. For clarity, the minimum storage volume size required for supporting online filesystem
creation by means of a filesystem creation info header is $16\cdot 4\cdot 128\textrm{B} = 8192\textrm{B}$. Note that
this scheme has been chosen such that the backup copy will get placed towards the storage volume's end, while still
preserving a relatively large alignment at the same time: having it stored near the end prevents it from intefering with
any of the filesystem's initial metadata structures' placement and the large alignment will enable meaningful error
reporting in case the underlying hardware is not compatible with the selected [IO Block](#def-io-block) size.

In either case, if no valid [image header](#sec-image-header) of either type passing the respective checksum
verification is found at the storage volume's beginning when attempting to open a filesystem, neither a [regular
CocoonFS static image header](#sec-static-image-header) nor a filesystem creation info header, then implementations are
expected to check for the presence of a filesystem creation info header backup copy at the specified location. If one is
found, and it passes its checksum verification, then the online filesystem creation procedure is supposed to get
restarted from scratch.


### [Key derivation]{#sec-key-derivation}
As outlined in the [introduction](#sec-introduction), the root key gets processed once through the TCG
[`KDFa()`](#bib-tcgtpm19a) with SHA-512 in order to thwart downgrade attacks. Furthermore subkeys are derived from that
for every combination of filesystem entity and cryptographic purpose in order to confine a potential key wear-out.

For reference in what follows, the input parameters to the `KDFa()` are specified in \[[TCGTPM19A](#bib-tcgtpm19a)\] as
follows:

* `hashAlg` - The [TCG Algorithm Registry](#bib-tcgalg25) identifier of the hash to be used for the KDF.
* `key` - The input key material.
* `label` - A variable sized octet stream.
* `context` - A variable sized octet stream used as the context.
* `bits` - The output key size in units of bits.

`label` is set to one of the following single-byte constants identifying the cryptographic purpose the derived key is to
be used for:

+-----------------------------------------+-----+----------------------------------------------------------------------+
|Name                                     |Value|Description                                                           |
+=========================================+=====+======================================================================+
|`KEY_PURPOSE_DERIVATION`                 |1    |The key will be used for [deriving further                            |
|                                         |     |keys](#sec-key-derivation-subkey) from it, by means of of             |
|                                         |     |[`kdf_hash_alg`](#def-image-layout).                                  |
+-----------------------------------------+-----+----------------------------------------------------------------------+
|`KEY_PURPOSE_AUTH_ROOT`                  |2    |The key will be used for forming the [authentication tree root        |
|                                         |     |HMAC](#sec-auth-tree-root-digest) with                                |
|                                         |     |[`auth_tree_root_hmac_hash_alg`](#def-image-layout).                  |
+-----------------------------------------+-----+----------------------------------------------------------------------+
|`KEY_PURPOSE_AUTH_DATA`                  |3    |The key will be used for forming an [HMAC over an Authentication Tree |
|                                         |     |Data Block](#sec-auth-tree-data-block-digest) with                    |
|                                         |     |[`auth_tree_data_hmac_hash_alg`](#def-image-layout).                  |
+-----------------------------------------+-----+----------------------------------------------------------------------+
|`KEY_PURPOSE_PREAUTH_CCA_PROTECTION_AUTH`|4    |The key will be used for some inline authentication HMAC formed with  |
|                                         |     |[`preauth_cca_protection_hmac_hash_alg`](#def-image-layout).          |
+-----------------------------------------+-----+----------------------------------------------------------------------+
|`KEY_PURPOSE_ENCRYPTION`                 |5    |The key will be used for encrypting with                              |
|                                         |     |[`block_cipher_alg`](#def-image-layout).                              |
+-----------------------------------------+-----+----------------------------------------------------------------------+

#### [Root key derivation]{#sec-key-derivation-root}
The root key is derived from the externally supplied key material by invoking `KDFa()` with its parameters set to:

* `hashAlg` - The [TCG Algorithm Registry](#bib-tcgalg25) identifier of SHA-512, i.e. `TPM_ALG_SHA512` or `0xd`.
* `key` - The raw key material supplied from extern.
* `label` - Constant `KEY_PURPOSE_DERIVATION`.
* `context` - The concatenation of
   1. The magic string `'COCOONFS'`, without a terminating zero byte.
   2. The image format version, fixed to 0, encoded as a single byte.
   3. [`kdf_hash_alg`](#def-image-layout) encoded as a 16 bit integer in big-endian format.
   4. [`auth_tree_root_hmac_hash_alg`](#def-image-layout) encoded as a 16 bit integer in big-endian format.
   5. [`auth_tree_node_hash_alg`](#def-image-layout) encoded as a 16 bit integer in big-endian format.
   6. [`auth_tree_data_hmac_hash_alg`](#def-image-layout) encoded as a 16 bit integer in big-endian format.
   7. [`preauth_cca_protection_hmac_hash_alg`](#def-image-layout) encoded as a 16 bit integer in big-endian format.
   7. [`block_cipher_alg`](#def-image-layout) encoded as a pair of two 16 bit integers, encoded in big-endian format
      each.
   8. The filesystem image salt as found in the [static image header](#sec-static-image-header), encoded as a single
      byte specifying the salt length, followed by the salt itself.
* `bits` - The digest size produced by the `hashAlg` of SHA-512, i.e. 512.

#### [Subkey derivation]{#sec-key-derivation-subkey}
The input parameters to subkey derivation are

* The derived key's cryptographic purpose, i.e. one of the constants defined in the table above.
* A pair of two 32 bit integers specifying a "domain" and "subdomain".

Unless otherwise noted, the domain is set to an inode number associated with the to be derived key and subdomain is one
of

+----------------------------------+-----+---------------------------------------------------------------+
|Name                              |Value|Description                                                    |
+==================================+=====+===============================================================+
|`INODE_KEY_SUBDOMAIN_DATA`        |1    |The key will be used for processing the inode's data.          |
+----------------------------------+-----+---------------------------------------------------------------+
|`INODE_KEY_SUBDOMAIN_EXTENTS_LIST`|2    |The key will be used for processing the inode's extents list.  |
+----------------------------------+-----+---------------------------------------------------------------+

The subkey is derived from the [root key](#sec-key-derivation-root) by
invoking `KDFa()` with its parameters set to:

* `hashAlg` - [`kdf_hash_alg`](#def-image-layout).
* `key` - The root key derived from externally supplied key material as described in the previous section above.
* `label` - A single byte set to the desired key purpose input as a parameter to the subkey derivation.
* `context` - The concatenation of the input "domain" and "subdomain" values, encoded as 32 bit integers in
  little-endian format each.
* `bits` - A key size suitable for the specified cryptographic purpose and determined as follows:

  +-----------------------------------------+--------------------------------------------------------------------+
  |Specified key purpose                    |Output key size                                                     |
  +=========================================+====================================================================+
  |`KEY_PURPOSE_DERIVATION`                 |Digest length produced by [`kdf_hash_alg`](#def-image-layout).      |
  +-----------------------------------------+--------------------------------------------------------------------+
  |`KEY_PURPOSE_AUTH_ROOT`                  |Digest length produced by                                           |
  |                                         |[`auth_tree_root_hmac_hash_alg`](#def-image-layout).                |
  +-----------------------------------------+--------------------------------------------------------------------+
  |`KEY_PURPOSE_AUTH_DATA`                  |Digest length produced by                                           |
  |                                         |[`auth_tree_data_hmac_hash_alg`](#def-image-layout).                |
  +-----------------------------------------+--------------------------------------------------------------------+
  |`KEY_PURPOSE_PREAUTH_CCA_PROTECTION_AUTH`|Digest length produced by                                           |
  |                                         |[`preauth_cca_protection_hmac_hash_alg`](#def-image-layout).        |
  +-----------------------------------------+--------------------------------------------------------------------+
  |`KEY_PURPOSE_ENCRYPTION`                 |Key size of the [`block_cipher_alg`](#def-image-layout).            |
  +-----------------------------------------+--------------------------------------------------------------------+

  Note that it is assumed here that the relevant property for the security strength of a HMAC is the preimage
  resistance of the underlying hash function, which is commonly estimated to equal its digest length.


## [Allocation bitmap]{#sec-allocation-bitmap}
The allocation bitmap tracks the filesystem image's [Allocation Blocks'](#def-allocation-block) allocation status in an
associated bit each: a bit is set if the corresponding Allocation Block is allocated. The bitmap is organized as an
array of unsigned 64 bit integers, henceforth denoted by "allocation bitmap words", with any excess bits corresponding
to a region beyond the [filesystem image size](#sec-mutable-image-header) set to 0. The region at the start of the
filesystem image storing the [image headers](#sec-image-header), as well as the one where the [journal log
head](#sec-journal) is located, are always allocated.

The Allocation Bitmap is stored in inode number 2, and the inode index B+-tree minimum fill level is such that it can
always be found through the [inode index entry leaf node](#def-inode-index-entry-leaf-node), in turn referenced from the
[mutable image header](#sec-mutable-image-header).

In order to support partial allocation bitmap updates, the encryption format deviates from the standard "[encrypted
extents](#sec-encryption-entity-extents)" one generally used for inodes: the allocation bitmap files' extents are
divided into blocks of size as specified by the
[`allocation_bitmap_file_block_allocation_blocks_log2`](#def-image-layout) filesystem configuration parameter, and each
one gets encrypted individually with the common [encrypted block format](#sec-encryption-entity-block). Even though the
maximum possible payload size of such an encrypted block is not necessarily a multiple of the bitmap word size, only an
integral number of bitmap words is stored in each block, the maximum possible to be specific. The encryption key used
for encrypting the individual file blocks a [a subkey derived from the root key](#sec-key-derivation-subkey) with the
domain parameter set to 2, i.e. the allocation bitmap file's associated inode number, a subdomain value of
`INODE_KEY_SUBDOMAIN_DATA`, and a key purpose of [`KEY_PURPOSE_ENCRYPTION`](#sec-key-derivation).

Note that this scheme on encrypting the allocation bitmap file block-wise does allow an adversary to determine which
parts of the allocations bitmap have changed between two updates, but is in line with the previously discussed
relaxation that [allocations are kept confidential only for data at reset](#sec-allocations-confidentiality).

Special constraints apply to the allocation bitmap file's extents on storage: their boundaries must all be aligned to
the [Authentication Tree Data Block](#def-auth-tree-data-block) size and their lengths must all be a multiple of the
allocation bitmap file block size. Note that the alignment to the Authentication Tree Data Block size is required for
bootstrapping authentication at filesystem opening time: in general an Authentication Tree Data Block's individual
Allocation Blocks' respective allocation status must be known each for [computing its authentication
digest](#sec-auth-tree-data-block-digest), but with the aligned allocation bitmap file extents all overlapping
Authentication Tree Data Blocks' Allocation Blocks are known a priori to be allocated.

## [Authentication tree]{#sec-auth-tree}
A Merkle tree construction is used for the authentication. All nodes' sizes are equal and is as specified by the
[`auth_tree_node_io_blocks_log2`](#def-image-layout). Leaf nodes store a number of digests of lengths as produced by
[`auth_tree_data_hmac_hash_alg`](#def-image-layout), as many as fit a node rounded down to the next power of two.  Each
digest entry in a leaf node authenticates an associated [Authentication Tree Data Block](#def-auth-tree-data-block),
which may comprise one or more [Allocation Blocks](#def-allocation-block) as specified by the
[`auth_tree_data_block_allocation_blocks_log2`](#def-image-layout) filesystem configuration parameter. Internal nodes
store a number of digests as produced by [`auth_tree_node_hash_alg`](#def-image-layout), as many as fit a node rounded
down to the next power of two. Each digest entry in an internal node authenticates an associated child node's
contents. A root HMAC digest is performed over the tree's root node (alongside some auxiliary information needed for
bootstrapping), which can be either a leaf or an internal node. The root HMAC digest fully captures all of the
filesystem's contents and is stored in the [mutable image header](#sec-mutable-image-header).

The authentication tree is stored in inode number 1 and inode index B+-tree minimum fill level is such that it that it
can always be found through the [inode index entry leaf node](#def-inode-index-entry-leaf-node), in turn referenced from
the [mutable image header](#sec-mutable-image-header).

All of the authentication tree's extents' boundaries must be aligned to the larger of an [IO Block](#def-io-block) and
an [Authentication Tree Data Block](#def-auth-tree-data-block). No leaf entry is associated with any storage region
overlapping with some of the authentication tree's extents -- the authenticated data ranges comprise all of the
filesystem image with the authentication tree's extents skipped. An authenticated [Allocation
Block's](#def-allocation-block) associated index on physical storage is converted to its containing Authentication Tree
Data Block's index in the [*Authentication Tree Data Block index domain*]{#def-auth-tree-data-block-index-domain} by
subtracting from it the accumulated lengths of any authentication tree extents located before it on physical storage and
converting the result to units of Authentication Tree Data Blocks, i.e. by shifting it to the right by a distance of
[`auth_tree_data_block_allocation_blocks_log2`](#def-image-layout) bits.

Any leaf node (data) digest entry is implicitly associated with an Authentication Tree Data Block index domain index by
means of its position in the tree with respect to tree order.

### [Authentication Tree Data Block digests]{#sec-auth-tree-data-block-digest}
When forming a given [Authentication Tree Data Block's](#def-auth-tree-data-block) digest, only its allocated
[Allocation Blocks'](#def-allocation-block) contents are considered. The reason is that in order to support the
journalling functionality, any Authentication Tree Data Block's digest must be reconstructible, but the contents of
unallocated Allocation Blocks must be assumed indeterminate -- it could have e.g. been used for temporarily storing the
dynamically allocated parts of the journal (or even been trimmed to begin with).

If a plain hash was directly used for digesting the Authentication Tree Data Blocks, an adversary could immediately
figure the allocation status of each of its constituent [Allocation Blocks](#def-allocation-block), simply by attempting
to recreate the digest found in the authentication tree by brute-forcing over a small search space. As the allocations
state is [considered confidential for data at rest](#sec-allocations-confidentiality), the Authentication Tree Data
Blocks are digested with a keyed HMAC instead. It should be stressed at this point that the HMAC serves only as a device
to efficiently obfuscate the digests, none of its security properties beyond those provided by the underlying hash are
relied upon authentication-wise. In particular, given that the allocations are considered confidential only in the data
at rest model, implementations are not required to make any provisions prohibiting their use as an HMACcing oracle. That
is, they may produce and expose HMAC digests for any data found on storage without verifying its authenticity first.

Digests for (virtual) [Authentication Tree Data Block's](#def-auth-tree-data-block) located completely after the
filesystem image's end, as determined by the image size field in the [mutable image header](#sec-mutable-image-header),
are set to all-zeros. Note that this is relevant for any "excess" entries in the authentication tree's leaf nodes tail.
Digests for Authentication Tree Data Blocks within the filesystem image range are formed as described in what follows.

The key used for producing an HMAC over an [Authentication Tree Data Block](#def-auth-tree-data-block) is [a subkey
derived from the root key](#sec-key-derivation-subkey) with the domain parameter set to 1, i.e. the authentication
tree's associated inode number, a subdomain value of 0, and a key purpose of
[`KEY_PURPOSE_AUTH_DATA`](#sec-key-derivation).

The HMAC is formed with a hash algorithm of [`auth_tree_data_hmac_hash_alg`](#def-image-layout) over

1. the [Authentication Tree Data Block's](#def-auth-tree-data-block) constituent allocated [Allocation
   Blocks](#def-allocation-block) contents, while skipping over the unallocated ones, as well as those allocated to the
   [image header](#sec-image-header) or journal log head,
2. and an [authentication context](#sec-auth-context) formed as follows:
   1. A 64 bit allocation bitmap word specifying the allocation status of each of the Authentication Tree Data Block's
      constituent Allocation Blocks, encoded in little-endian format.
   2. The Authentication Tree Data Block's Authentication Tree Data Block's index in the Authentication Tree Data Block
      index domain, encoded as a 64 bit integer in little-endian format.
   4. An authentication context format version identifier byte of constant 0.
   5. An authentication context subject identifier byte of constant
      [`AUTH_SUBJECT_ID_AUTH_TREE_DATA_BLOCK`](#def-auth-subject-id) identifying the authenticated subject.

### [Authentication tree non-root node digests]{#sec-auth-tree-descendant-node-digest}
The internal, i.e. non-leaf nodes store digests over their child nodes each. Note that each subtree rooted at a child
effectively covers a certain associated data range, with that range's length in units of Authentication Tree Data Blocks
being a power of two.

Digests for children covering a data range located completely after the filesystem image's end, as determined by the
image size field in the [mutable image header](#sec-mutable-image-header), are set to all-zeros. Digests for child nodes
whose an associated data range overlaps with the filesystem image range are formed as described in what follows.

The digest over a child node is produced by computing the (regular) hash with [`auth_tree_node_hash_alg`](#def-image-layout) over

1. the digests stored in the child node back to back
2. and an [authentication context](#sec-auth-context) formed as follows:
   1. The index in the [Authentication Tree Data Block index domain](#def-auth-tree-data-block-index-domain) of the
      child's last entry's associated data region's beginning, encoded as a 64 bit integer in little-endian
      format. Observe that this uniquely fixes the position of the child node in the tree.
   2. An authentication context format version identifier byte of constant 0.
   3. An authentication context subject identifier byte of constant
      [`AUTH_SUBJECT_ID_AUTH_TREE_DESCENDANT_NODE`](#def-auth-subject-id) identifying the authenticated subject.

### [Authentication tree root node digest](#sec-auth-tree-root-digest)
The authentication tree root digest is created by computing a HMAC with an underlying hash of
[`auth_tree_root_hmac_hash_alg`](#def-image-layout) and a [a subkey derived from the root
key](#sec-key-derivation-subkey) with the domain parameter set to 1, i.e. the authentication tree's associated inode
number, a subdomain value of 0, and a key purpose of [`KEY_PURPOSE_AUTH_ROOT`](#sec-key-derivation) over

1. the digests stored in the root node back to back
2. and an [authentication context](#sec-auth-context) formed as follows:
   1. The index in the [Authentication Tree Data Block index domain](#def-auth-tree-data-block-index-domain) of the root
      node's last entry's associated data region's beginning modulo $2^{64}$, encoded as a 64 bit integer in
      little-endian format. Observe that this uniquely fixes the position of the root node in the tree.
   2. The "image context", a digest over filesystem configuration parameters computed as described below.
   3. An authentication context format version identifier byte of constant 0.
   4. An authentication context subject identifier byte of constant
      [`AUTH_SUBJECT_ID_AUTH_TREE_ROOT_NODE`](#def-auth-subject-id) identifying the authenticated subject.

The image context digest is produced by forming a HMAC with same hash algorithm and subkey as for the root node above
over

1. The magic `'COCOONFS'`, without a terminating zero byte.
2. A single byte filesystem format version identifier of constant 0.
3. The [encoded image layout](#def-image-layout).
4. The [encoded block pointer](#sec-enc-block-ptr) to the [inode index entry leaf
   node](#def-inode-index-entry-leaf-node), as found in the [mutable image header](#sec-mutable-image-header).
5. The filesystem image size in units of [Allocation Blocks](#def-allocation-block), as found in the [mutable image
   header](#sec-mutable-image-header).
6. The [authentication tree's](#sec-auth-tree) extents, represented in the common [extents list
   format](#sec-enc-extents-list).
7. The [allocation bitmap file's](#sec-allocation-bitmap) extents, represented in the common [extents list
   format](#sec-enc-extents-list).
8. An authentication context format version identifier byte of constant 0.
9. An authentication context subject identifier byte of constant [`AUTH_SUBJECT_ID_IMAGE_CONTEXT`](#def-auth-subject-id)
   identifying the authenticated subject.

Note that the image contexts binds

* All information required for interpreting any of the filesystem's encoded structures.
* The mapping of physical locations into the [Authentication Tree Data Block index
  domain](#def-auth-tree-data-block-index-domain), by virtue of the authentication tree's extents.
* The location of the [inode index entry leaf node](#def-inode-index-entry-leaf-node) serving as the entry point for
  locating any other filesystem entity on storage. That effectively makes the authentication tree to not only
  authenticate the raw data, but also the full metadata hierarchy, i.e. what's being stored where.
* The locations of the [allocation bitmap file's](#sec-allocation-bitmap) extents are included explicitly, because they
  need to get read for bootstrapping the authentication, before the authentication tree is available.

Note that in principle the encoded image context could have been included verbatim in the data the authentication tree
root digest is getting computed over. However, for reasons of efficiency, an intermediate digest is performed over the
image context first, which gets then in turn considered in the computation of the authentication tree root digest -- the
image context's contents are expected to change only infrequently if at all, whereas the root digest needs to get
recomputed upon every filesystem update.

### Organization of the authentication tree storage
The authentication tree's nodes are serialized back to back in the tree's DFS PRE order into the tree's associated
extents. A node's digests are located back to back at the beginning of its associated storage area, any padding to align
the node size up to the length specified by [`auth_tree_node_io_blocks_log2`](#def-image-layout) is retained on storage.

Note that it is possible to deduce the authentication tree's dimensions from its extents' total length and
implementations are required to do so at filesystem opening time. The alignment constraints on the extents' boundaries
may result in more nodes being stored than is required to cover all of the filesystem image. As outlined in the previous
sections, excess digest entries are to be set to all zeros.

When deducing the authentication tree dimensions from the extents' total length, implementations must cap the height at
$$\textrm{min}\left\{\left\lceil\frac{W}{c}\right\rceil, \left\lceil\frac{W - d - a}{c}\right\rceil + 1\right\}$$ with
$W=64$, $c$ denoting the base-2 logarithm of the number of digest entries in a non-leaf node, $d$ denoting the base-2
logarithm of the number of digests in a leaf node and $a$ the base-2 logarithm of the number of [Allocation
Blocks](#def-allocation-block) in an [Authentication Tree Data Block](#def-auth-tree-data-block),
i.e. [`auth_tree_data_block_allocation_blocks_log2`](#def-image-layout). Imposing this upper limit on the tree height
does not restrict the data range coverable by an authentication tree (to below the maximum supported filesystem image
size), but ensures that

* the number of nodes in a full tree at that height is representable as a 64 bit integer,
* the length of a range covered by any proper subtree in units of [Allocation Blocks](#def-allocation-block) is
  representable as a 64 bit integer.

## [Inode index]{#sec-inode-index}
Inodes are identified by positive 32 bit integers. The inode index tracks the allocated inodes and their associated
locations on storage each, either by means of a direct [encoded extent pointer](#sec-enc-extent-ptr) or by an "indirect"
pointer pointing to the head of some [chained extents](#sec-encryption-entity-chained-extents) storing the inode's
[extents list](#sec-enc-extents-list).

The inode index is organized as a B+-tree, with a node size as specified by the
[`index_tree_node_allocation_blocks_log2`](#def-image-layout) filesystem configuration parameter.

The minimum leaf node fill level is constrained to be >= 4, so that inodes 1-4 are always found in the leftmost leaf
node, the [*inode index entry leaf node*]{#def-inode-index-entry-leaf-node}. The location of the inode index entry leaf
node is specified in the [mutable image header](#sec-mutable-image-header). Among those four special inodes is inode 3
allocated to the inode index root node. The index entry for this inode must always specify the location of the index
root node in terms of a direct [encoded extent pointer](#sec-enc-extent-ptr), an indirect extents list is not permitted
for it.

The index' individual nodes are [encrypted as blocks](#sec-encryption-entity-block) each, with a [a subkey derived from
the root key](#sec-key-derivation-subkey) with the domain parameter set to 3, i.e. the inode index' associated inode
number, a subdomain value of `INODE_KEY_SUBDOMAIN_DATA`, and a key purpose of
[`KEY_PURPOSE_ENCRYPTION`](#sec-key-derivation).

### Inode index leaf node format
Let $B$ denote a decrypted index node's maximum possible payload size in units of bytes. The maximum number of entries
in a leaf node is then given by $M_{\textrm{leaf}} = \left\lfloor\frac{B - 12}{12}\right\rfloor$. The minimum leaf node
fill level is set to $m_\textrm{leaf} = \left\lceil\frac{M_\textrm{leaf}}{2}\right\rceil$. $B$ must be large enough so
that the constraint $m_\textrm{leaf} >= 4$ holds. Note that with a minimum inode index block size of 128B, and a maximum
IV length of 32B, the $m_\textrm{leaf} >= 4$ is automatically fulfilled.

The leaf node format is as follows:

+---------------------------------------------------------------+------------------------------------------------------+
|Range in units of bytes                                        |Description                                           |
+===============================================================+======================================================+
|$0$ to $8$                                                     |[Encoded block pointer](#sec-enc-block-ptr) to the    |
|                                                               |next leaf node in tree order, if any, or NIL          |
|                                                               |otherwise.                                            |
+---------------------------------------------------------------+------------------------------------------------------+
|$8$ to $8 + 8\cdot M_\textrm{leaf}$                            |The inode entries associated [encoded extent          |
|                                                               |pointers](#sec-enc-extent-ptr).                       |
+---------------------------------------------------------------+------------------------------------------------------+
|$8 + 8\cdot M_\textrm{leaf}$ to $8 + 12\cdot M_\textrm{leaf}$  |The inode entries associated keys, i.e. the inode     |
|                                                               |numbers, encoded as 32 bit integers in little endian  |
|                                                               |format.                                               |
+---------------------------------------------------------------+------------------------------------------------------+
|$8 + 12\cdot M_\textrm{leaf}$ to $12 + 12\cdot M_\textrm{leaf}$|The node level, fixed to 1 for leaf nodes, encoded as |
|                                                               |a 32 bit integer in little-endian format.             |
+---------------------------------------------------------------+------------------------------------------------------+

For $i\in\{0\ldots M_\textrm{leaf} - 1\}$, the i'th [encoded extent pointer](#sec-enc-extent-ptr) is associated with the
i'th key. Unoccupied entries have a key value of 0, i.e. the special "no inode" value, and an encoded extent pointer
value of NIL. The unoccupied slots must all be at the tail. The occupied entries must be sorted by the inode number. No
leaf node with less than $m_\textrm{leaf}$ nodes may exist, except for possibly at the tree root.

### Inode index internal node format
Let $B$ denote a decrypted index node's maximum possible payload size in units of bytes again. The maximum number of
entries, i.e. separating keys, in an internal node is then given by $M_{\textrm{internal}} = \left\lfloor\frac{B -
12}{12}\right\rfloor$. The minimum internal node fill level is set to $m_\textrm{internal} =
\left\lfloor\frac{M_\textrm{internal} - 1}{2}\right\rfloor$.

Implementations might want to preemptively split full nodes or merge pairs of nodes at minimum fill level when walking
down a path from the root for insertion or deletion. By coincidence, $M_\textrm{internal} = M_\textrm{leaf}$ and from
the constraint $m_\textrm{leaf} >= 4$, it follows that $M_\textrm{internal} = M_\textrm{leaf} >= 7 > 2$, as is required
for supporting preemptive node splitting of full nodes. Note that $m_\textrm{internal}$ has been defined specifically in
a way to enable preemptive splitting of full nodes as well as merging nodes at the minimum fill level, even for even
values of $M_\textrm{internal}$.

+-----------------------------------------------------------------------+----------------------------------------------+
|Range in units of bytes                                                |Description                                   |
+=======================================================================+==============================================+
|$0$ to $8 + 8\cdot M_\textrm{internal}$                                |[Encoded block pointers](#sec-enc-block-ptr)  |
|                                                                       |to the node's children.                       |
+-----------------------------------------------------------------------+----------------------------------------------+
|$8 + 8\cdot M_\textrm{internal}$ to $8 + 12\cdot M_\textrm{internal}$  |The separator keys, encoded as 32 bit integers|
|                                                                       |in little-endian format.                      |
+-----------------------------------------------------------------------+----------------------------------------------+
|$8 + 12\cdot M_\textrm{internal}$ to $12 + 12\cdot M_\textrm{internal}$|The node level, counted 1-based from the leaf |
|                                                                       |upwards, encoded as a 32 bit integer in       |
|                                                                       |little-endian format.                         |
+-----------------------------------------------------------------------+----------------------------------------------+

For $i\in\{0\ldots M_\textrm{internal} - 1\}$, the i'th key is the separator key between the $i$'th and $(i + 1)$'th
child -- inode entries stored under the left child have an inode value all strictly less than the separator key, inode
entries stored under the right child have an inode value greater than or equal to the separator key value. Unoccupied
entries have a key value of 0, i.e. the special "no inode" value, and the block pointer to the associated right child is
NIL. The unoccupied slots must all be at the tail. The occupied entries must be sorted by the inode number. No internal
node with less than $m_\textrm{internal}$ occupied key entries may exist except for possibly at the tree root, which
must still have at least two children and a separator key inbetween.

### [Inode index entry leaf node preauthentication CCA protection digest]{#sec-inode-index-entry-leaf-node-preauth-digest}
The [inode index entry leaf node](#def-inode-index-entry-leaf-node), i.e. the first leaf node in tree order, serves as
the entry point when opening the filesystem, and its location is specified in the [mutable image
header](#sec-mutable-image-header) accordingly.  However, it needs to get decrypted before the full authentication tree
based authentication has become functional, and therefore must first get authenticated by some other means before
starting the decryption.

For this purpose, a HMAC over the entry leaf node is stored in the [mutable image header](#sec-mutable-image-header).
This HMAC is created with an underlying hash algorithm of [`preauth_cca_protection_hmac_hash_alg`](#def-image-layout)
and [a subkey derived from the root key](#sec-key-derivation-subkey) with the domain parameter set to 3, i.e. the inode
index' associated inode number, a subdomain value of `INODE_KEY_SUBDOMAIN_DATA`, and a key purpose of
[`KEY_PURPOSE_PREAUTH_CCA_PROTECTION_AUTH`](#sec-key-derivation), over

1. the encrypted entry leaf node's data, of size as determined by
   [`index_tree_node_allocation_blocks_log2`](#def-image-layout)
2. and an [authentication context](#sec-auth-context) formed as follows:
   1. [`block_cipher_alg`](#def-image-layout) encoded as a pair of two 16 bit integers, encoded in big-endian format
      each.
   2. An authentication context format version identifier byte of constant 0.
   3. An authentication context subject identifier byte of constant
      [`AUTH_SUBJECT_ID_INODE_INDEX_NODE`](#def-auth-subject-id) identifying the authenticated subject.

### Inode extents lists
The inode entries stored in the index tree's leaf nodes have an associated [encoded extent pointer](#sec-enc-extent-ptr)
each for specifying an inode's location on storage. This extent pointer can either be direct or indirect. If direct, it
encodes the location and dimensions of an inode's (single) extent on storage. If indirect, it points to the head extent
in a list of [encrypted chained extents](#sec-encryption-entity-chained-extents) collectively storing the inode's
[encoded extents list](#sec-enc-extents-list).

For encryption in the [encrypted chained extents](#sec-encryption-entity-chained-extents) format, a [a subkey is derived
from the root key](#sec-key-derivation-subkey) with the domain parameter set to the respective inode number, a subdomain
value of `INODE_KEY_SUBDOMAIN_EXTENTS_LIST`, and a key purpose of [`KEY_PURPOSE_ENCRYPTION`](#sec-key-derivation).

The authentication tree and allocation bitmap files need to get located at filesystem opening time in order to bootstrap
the full tree based authentication. Therefore, the inline authenticated variant of the [encrypted chained
extents](#sec-encryption-entity-chained-extents) format is used for storing these two files' extents lists, if any. The
hash algorithm used for this is the [`preauth_cca_protection_hmac_hash_alg`](#def-image-layout), the HMAC key is set to
[a subkey derived from the root key](#sec-key-derivation-subkey) with the domain parameter set to the inode number, a
subdomain value of `INODE_KEY_SUBDOMAIN_EXTENTS_LIST`, and a key purpose of
[`KEY_PURPOSE_PREAUTH_CCA_PROTECTION_AUTH`](#sec-key-derivation). The authenticated associated data for the encrypted
chained extents' inline authentication is set to

1. The inode number as a 32 bit integer, encoded in little-endian format.
2. A format version identifier byte of constant 0.
3. An identifier byte of constant 2 identifying the type of authenticated associated data for the encrypted chained
   extents' inline authentication.

## Regular file encryption
Except for the special case of the [allocation bitmap file](#sec-allocation-bitmap), any file's data is stored in
[encrypted extents](#sec-encryption-entity-extents), with the set of extents specified by its corresponding entry in the
[inode index](#sec-inode-index).

The key used for the encryption is [a subkey derived from the root key](#sec-key-derivation-subkey) with the domain
parameter set to the inode number, a subdomain value of `INODE_KEY_SUBDOMAIN_DATA`, and a key purpose of
[`KEY_PURPOSE_ENCRYPTION`](#sec-key-derivation).

## [Journal]{#sec-journal}
The journal contains all the information needed to apply pending changes at filesystem opening time following a possible
service interruption. From a high level, it consists of *staging copies* of the to be written data at [IO
block](#def-io-block) granularity and a log specifying what needs to get written where as well as information about
which parts of the the [authentication tree](#sec-auth-tree) need a reconstruction.

The journal log is stored in a list of [encrypted chained extents](#sec-encryption-entity-chained-extents), with the
head extent, the [*journal log head*](#def-journal-log-head), being located at a fixed position in the filesystem image,
which can get determined from the information provided in the [static image header](#sec-static-image-header). More
specifically, the journal log head extent is located at the first [IO Block](#def-io-block) and [Authentication Tree
Data Block](#def-auth-tree-data-block) aligned boundary following the [mutable image
header's](#sec-mutable-image-header). Its length is set to the least multiple of the larger of the [IO
block](#def-io-block) and [Authentication Tree Data Block](#def-auth-tree-data-block) size sufficient for storing the
minimum possible [encrypted chained extents'](#sec-encryption-entity-chained-extents) head. The journal log tail extents
as well as the data staging copies are stored at arbitrary, otherwise unallocated locations, with the constraint that
all extents' boundaries must be aligned to the [IO Block](#def-io-block) size. Note that the journal log head extent is
constrained to be aligned to the [Authentication Tree Data Block](#def-auth-tree-data-block) size only for the
convenience of implementations: for the purpose of computing ["authentication tree data block
digests"](sec-auth-tree-data-block-digest), the journal log head extent is to be considered as if unallocated as a
special case, and letting it occupy an integral multiple of the Authentication Tree Data Block size alleviates the need
to implement range checks for detecting this special case when updating potentially neighboring data.

The journal log's encrypted chained extents are encrypted with a [a subkey is derived from the root
key](#sec-key-derivation-subkey) with the domain parameter set to 5, i.e. the inode number allocated to the (virtual)
journal log file, a subdomain value of `INODE_KEY_SUBDOMAIN_DATA`, and a key purpose of
[`KEY_PURPOSE_ENCRYPTION`](#sec-key-derivation). The constituent extents are inline authenticated with a HMAC with
underlying hash algorithm as specified by [`preauth_cca_protection_hmac_hash_alg`](#def-image-layout), a subkey is
derived from the root key with the domain parameter also set to 5, a subdomain value of `INODE_KEY_SUBDOMAIN_DATA`, and
a key purpose of [`KEY_PURPOSE_PREAUTH_CCA_PROTECTION_AUTH`](#sec-key-derivation). The authenticated associated data for
the encrypted chained extents' inline authentication is set to

1. The [encoded image layout](#def-image-layout).
2. A format version identifier byte of constant 0.
3. An identifier byte of constant 1 identifying the type of authenticated associated data for the encrypted chained
   extents' inline authentication.

The journal is to be considered non-empty and to get applied upon the next filesystem opening following a possible
service interruption whenever its head extent begins with a magic of `'CCFSJRNL'`, without a terminating zero byte, and
the head extent's inline authentication digest successfully verifies its contents. Note that the head extent's inline
authentication digest serves as an integrity protection measure here, in particular it is not an error if the head
extent's authentication fails -- in this case the journal is simply considered as having been only partially written and
is disregarded.

It is expected that implementations would write all of the journal's data before the journal log head extent, issuing
write barriers as is appropriate for the underlying hardware device inbetween. Similarly, after the journal has been
applied, either online or following a service interruption, it is expected that implementations would first invalidate
the journal log head extent before proceeding to reusing any of the storage areas occupied by the journal's remainder,
likewise issuing write barriers as needed. In particular failure to authenticate a journal log tail extent when the head
authenticated successfully is a fatal error.

The journal log plaintext is organized as sequence of tag-length-value (TLV) encoded fields. The tag and length are
encoded as unsigned integers in LEB128 format, the format of the value depends on the field. The fields must be stored
in the journal in the order induced by increasing tag values. The defined tag values are:

+----------------------------------------------------------------+-----+-----------------------------------------------+
|Name                                                            |Value|Description                                    |
+================================================================+=====+===============================================+
|`JOURNAL_LOG_FIELD_TAG_AUTH_TREE_EXTENTS`                       |1    |Mandatory. The authentication tree's [encoded  |
|                                                                |     |extents list](#sec-enc-extents-list).          |
+----------------------------------------------------------------+-----+-----------------------------------------------+
|`JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_EXTENTS`               |2    |Mandatory. The allocation bitmap file's        |
|                                                                |     |[encoded extents list](#sec-enc-extents-list). |
+----------------------------------------------------------------+-----+-----------------------------------------------+
|`JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_FRAGMENTS_AUTH_DIGESTS`|3    |Mandatory. Authentication digests of allocation|
|                                                                |     |bitmap file fragments needed for reconstructing|
|                                                                |     |the authentication tree.                       |
+----------------------------------------------------------------+-----+-----------------------------------------------+
|`JOURNAL_LOG_FIELD_TAG_APPLY_WRITES_SCRIPT`                     |4    |Mandatory. List of data updates to replay.     |
+----------------------------------------------------------------+-----+-----------------------------------------------+
|`JOURNAL_LOG_FIELD_TAG_UPDATE_AUTH_DIGESTS_SCRIPT`              |5    |Mandatory. List of authentication tree updates |
|                                                                |     |to replay.                                     |
+----------------------------------------------------------------+-----+-----------------------------------------------+
|`JOURNAL_LOG_FIELD_TAG_TRIM_SCRIPT`                             |6    |Optional. List of trim operations to issue     |
|                                                                |     |after the journal has been replayed.           |
+----------------------------------------------------------------+-----+-----------------------------------------------+
|`JOURNAL_LOG_FIELD_TAG_JOURNAL_STAGING_COPY_DISGUISE`           |7    |Optional. Encryption parameters used for       |
|                                                                |     |disguising the journal's data staging copies.  |
+----------------------------------------------------------------+-----+-----------------------------------------------+

### Allocation bitmap file fragments' authentication digests
Whenever [replaying any authentication tree node entry update](#sec-journal-auth-tree-updates-script) from the journal
at filesystem opening time, the complete node must get reconstructed in full from scratch: the nodes' boundaries are
aligned to the [IO Block](#def-io-block) size each, but some previous attempt to apply the journal might have failed and
left the nodes' contents in an indeterminate state.

For recreating the data digests at the leaf level, i.e. [computing the Authentication Tree Data Blocks'
digests](#sec-auth-tree-data-block-digest), the allocation status of each constituent [Allocation
Block](#def-allocation-block) must be known. Therefore, those parts of the [allocation bitmap
file](#sec-allocation-bitmap) that track the data ranges covered by the affected authentication tree leaf nodes must get
read. Remember that the allocation bitmap is encrypted in units of allocation bitmap file blocks, so it is possible to
decrypt only those fragments needed for the authentication tree reconstruction during journal replay. However, for
maintaining IND-CCA security, the encrypted contents must get authenticated before a decryption is attempted.

The journal log field with tag `JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_FRAGMENTS_AUTH_DIGESTS` provides all of the
[Authentication Tree Data Block](#def-auth-tree-data-block) digests overlapping with any of the allocation bitmap file
fragments needed for reconstructing the authentication tree from journal replay. Those digests are over the updated
allocation bitmap data, i.e. over the allocation bitmap ciphertext fragments as if the journal had been replayed
already.

The field's value contents is constructed by concatenating

1. A sequence of records, one for each of the allocation bitmap file's covered [Authentication Tree Data
   Block](#def-auth-tree-data-block), encoded as pairs of location and digest each. The location of the respective
   Authentication Tree Data Block is encoded as the difference between its beginning on physical storage relative to the
   previous record's associated Authentication Tree Data Block's end, if any, or 0 otherwise, converted to units of
   Authentication Tree Data Blocks, and encoded as an unsigned integer in LEB128 format. The Authentication Tree Data
   Block digest, of size as determined by the [`auth_tree_data_block_allocation_blocks_log2`](#def-image-layout)
   parameter, is serialized right after that.
   
   Remember that all of the [allocation bitmap file's](#sec-allocation-bitmap) extents' boundaries are constrained to be
   aligned to the [Authentication Tree Data Block](#def-auth-tree-data-block) size, hence no such block can overlap only
   partially with the file. It is an error if any of the allocation bitmap file's encryption blocks is covered only
   partially by the collective set of records in this journal log field: any must be either not covered at all or in
   full.
2. An authentication HMAC with an underlying hash algorithm of
   [`preauth_cca_protection_hmac_hash_alg`](#def-image-layout) and [a subkey is derived from the root
   key](#sec-key-derivation-subkey) with the domain parameter set to 2, i.e. the allocation bitmap files associated
   inode number, a subdomain value of `INODE_KEY_SUBDOMAIN_DATA`, and a key purpose of
   [`KEY_PURPOSE_PREAUTH_CCA_PROTECTION_AUTH`](#sec-key-derivation) over
   
   1. The [encoded image layout](#def-image-layout).
   2. The allocation bitmap file's [encoded extents list](#sec-enc-extents-list).
   3. The journal log field's records encoded as above.
   4. An [authentication context](#sec-auth-context) constructed as follows:
      1. A format version identifier byte of constant 0 identifying the inner format.
	  2. The value `JOURNAL_LOG_FIELD_TAG_ALLOC_BITMAP_FILE_FRAGMENTS_AUTH_DIGESTS` represented as a single byte
	  3. A format version identifier byte of constant 0 identifying the outer "envelope" format.
      4. The value of [`AUTH_SUBJECT_ID_JOURNAL_LOG_FIELD`](#sec-auth-context) encoded as a single byte.
	  
### [Writes application script]{#sec-journal-apply-writes-script-script}
The journal log contains instructions how to apply pending data updates, more specifically which journal staging copies
to write to which target location. This information is encoded in a journal log field with a tag value of
`JOURNAL_LOG_FIELD_TAG_APPLY_WRITES_SCRIPT` as a sequence of records, each one consisting of

1. The beginning of the target location on physical storage, represented as the difference to the previous record's
   associated target range's end, if any, or 0 otherwise, converted to units of [IO Blocks](#def-io-block), and encoded
   as an unsigned integer in LEB128 format.
2. The beginning of the source location on physical storage, i.e. of the journal staging copy, represented as the
   difference to the previous record's associated source range's end, if any, or 0 otherwise, in units of [IO
   Blocks](#def-io-block) and taken modulo $2^{64}$, encoded as a signed integer in LEB128 format.
3. The range's length, in units of [IO Blocks](#def-io-block) and encoded as an unsigned integer in LEB128 format. It
   must not be zero.

The sequence is terminated with a termination records of three consecutive zero bytes.

No target region may overlap with any source region, with the exception that the two may be equal for a given record, in
which case implementations must skip it.

### [Authentication tree update script]{#sec-journal-auth-tree-updates-script}
The journal log field with tag `JOURNAL_LOG_FIELD_TAG_UPDATE_AUTH_DIGESTS_SCRIPT` contains all information needed to
update the authentication tree, namely a list of [Authentication Tree Data Blocks](#def-auth-tree-data-block) whose
[digests](#sec-auth-tree-data-block-digest) have changed -- either because their contents got updated or because some of
the constituent [Allocation Blocks](#def-allocation-block) got deallocated, or both.

The journal's [writes application script](#sec-journal-apply-writes-script-script) is not considered for the purpose of
determining which [Authentication Tree Data Blocks](#def-auth-tree-data-block)'s digests have changed, and is queried
only for possibly retrieving the updated contents of any data range referenced from the authentication tree update
script. In particular, the authentication tree update script must be complete.

The field contains a sequence of records, each encoded as

1. The beginning of the authenticated data range on physical storage, represented as the difference to the previous
   record's associated range's end, if any, or 0 otherwise, converted to units of [Authentication Tree Data
   Blocks](#def-auth-tree-data-block) and encoded as an unsigned integer in LEB128 format.
2. The length of the authenticated range in units of [Authentication Tree Data Blocks](#def-auth-tree-data-block),
   encoded as an unsigned integer in LEB128 format. It must not be zero.
   
The sequence is terminated with a termination records of two consecutive zero bytes.

It should be stressed that implementations must always reconstruct any modified authentication tree node from scratch
when replaying the journal: a previous attempt to write to it might have failed and the contents must therefore be
assumed to be in an indeterminate state.

### Trim script
A journal log may contain an optional field of tag `JOURNAL_LOG_FIELD_TAG_TRIM_SCRIPT` for specifying a sequence of
ranges to issue trim commands on after the journal has been replayed and the journal log head invalidated.

The field contains a sequence of records, each encoded as

1. The beginning of the to be trimmed range on physical storage, represented as the difference to the previous record's
   associated range's end, if any, or 0 otherwise, converted to units of [IO Blocks](#def-io-block) and encoded as an
   unsigned integer in LEB128 format.
2. The length of the to be trimmed range in units of [IO Blocks](#def-io-block), encoded as an unsigned integer in
   LEB128 format. It must not be zero.
   
The sequence is terminated with a termination records of two consecutive zero bytes.

If the field is present, then any of the journal staging copies referenced from records in the [writes application
script](#sec-journal-apply-writes-script-script), with the target range not being equal to the journal staging copy
range, get implicitly added to it, as do the journal log's tail extents.

### [Journal staging copy disguising]{#sec-journal-staging-copy-disguise}
For each record in the [writes application script](#sec-journal-apply-writes-script-script), the specified journal
staging copy is to get copied over to the target destination during journal replay. This enables adversaries to identify
the journal staging copy blocks as such, simply by attempting to find pairs of blocks with identical contents. As the
journal staging copies' backing storage is always tracked as unallocated, this leaks information about the allocations
state, which violates the principle that allocations are considered confidential for data at rest.

To restore the confidentiality of allocations for data at rest, the journal staging copies may -- at users' option -- get
encrypted with a one-time key. Note that this additional layer of encryption is computationally expensive, hence the
feature is optional and can get enabled on a per-transaction basis.

If a journal log field with a tag of `JOURNAL_LOG_FIELD_TAG_JOURNAL_STAGING_COPY_DISGUISE` is present, then journal
staging copy disguising is enabled, with the encryption algorithm and key as specified in the encoded field value:

1. The block cipher algorithm as a [TCG algorithm identifier](#bib-tcgalg25), encoded as a 16 bit integer in big-endian
   format.
2. The selected key size in bits, encoded as a 16 bit integer in big-endian format.
3. The encryption key of length as specified by the key size.
4. The IV generation encryption key of length as specified by the key size.

The journal staging copy disguising is implemented by encrypting each [Allocation Block](#def-allocation-block) from the
journal staging copy with the specified block cipher in CBC mode and an IV obtained as follows:

1. Concatenate the [Allocation Block's](#def-allocation-block) target location to its journal staging copy location,
   both represented as Allocation Block indices within the filesystem image and encoded as 64 bit integers in
   little-endian format.
2. Truncate or pad the result at the beginning so that its length becomes equal to the block cipher block size.
3. Encrypt the single block cipher block with the IV generation encryption key.

## Opening the filesystem (informative)
In order to illustrate how the various pieces needed for opening the filesystem fit together, especially with respect to
bootstrapping the authentication, the opening process is outlined below:

1.  Read the [static image header](#sec-static-image-header), i.e. the various filesystem configuration parameters and
    the salt.
2.  [Derive the root key from externally supplied key material](#sec-key-derivation-root).
3.  Determine the locations of the [journal log head extent](#sec-journal) as well as of the [mutable image
    header](#sec-mutable-image-header).
4.  Check whether there's a valid [journal](#sec-journal) at the journal log head extent location, if so apply it.
5.  Read the [mutable image header](#sec-mutable-image-header). This yields the [authentication tree root
    digest](#sec-auth-tree-root-digest), the location of the [inode index entry leaf
    node](#def-inode-index-entry-leaf-node) and its [preauthentication CCA protection
    digest](#sec-inode-index-entry-leaf-node-preauth-digest).
6.  Read the inode index entry leaf node, authenticate it against its preauthentication CCA protection digest and
    decrypt it.
7.  Lookup the [authentication tree](#sec-auth-tree) and [allocation bitmap file](#sec-allocation-bitmap) inodes in the
    decrypted inode index entry leaf node. Remember that the minimum inode index B+-tree minimum leaf node fill level
    is defined so that inodes 1-4 will always be found in that node.
8.  If the inode index entries for the authentication tree or allocation bitmap files contain indirect references to
    [extents lists](#sec-enc-extents-list), stored in the inline authenticated variant of the [encrypted chained
    extents](#sec-encryption-entity-chained-extents), then decrypt while verifying against the inline authentication.
9.  The allocation bitmap file's extents are constrained to all be aligned to the [Authentication Tree Data
    Block](#def-auth-tree-data-block) size, in particular any Authentication Tree Data Block overlapping with it is a
    proper subrange and has all of its constituent [Allocation Blocks](#def-allocation-block) allocated. Therefore, all
    information needed for [digesting the Authentication Tree Data Blocks](#sec-auth-tree-data-block-digest) overlapping
    with the allocation bitmap file's extents and authenticating them through the authentication tree is available.
    Furthermore, the [authentication tree root digest](#sec-auth-tree-root-digest) binds the location of the allocation
    bitmap file's extents on storage.
   
    Authenticate the allocation bitmap file's contents through the authentication tree and decrypt it afterwards. Once
	the allocation bitmap has been read, the information needed for [digesting any Authentication Tree Data
	Block](#sec-auth-tree-data-block-digest) is available.
10. Note that the [authentication tree root digest](#sec-auth-tree-root-digest) also binds the location of the [inode
    index entry leaf node](#def-inode-index-entry-leaf-node). Re-authenticate that node's encrypted contents, this time
    through the authentication tree.
11. The authentication of the filesystem through the authentication tree has been bootstrapped now.
12. Lookup the inode index root node inode in the [inode index entry leaf node](#def-inode-index-entry-leaf-node). Read
    it, authenticate it through the authentication tree and decrypt it.
13. The filesystem is now operational.

## [Bibliography]{#sec-bibliography}
* [FRUHWIRTH05 - "New Methods in Hard Disk Encryption", Clemens Fruhwirth, 2005, Vienna University of Technology,
  Institute for Computer Languages,
  [https://clemens.endorphin.org/nmihde/nmihde-A4-ds.pdf](https://clemens.endorphin.org/nmihde/nmihde-A4-ds.pdf)]{#bib-fruhwirth05}
* [GOLDREICH09 - "Foundations of Cryptography, Volume 2: Basic Applications", Oded Goldreich, Cambridge University
  Press, 2009, [https://www.cambridge.org/9780521119917](https://www.cambridge.org/9780521119917)]{#bib-goldreich09}
* [KHATI16 - "Full Disk Encryption: Bridging Theory and Practice", Louiza Khati, Nicky Mouha and Damien Vergnaud,
  Cryptology ePrint Archive, Paper 2016/1114, 2016,
  [https://eprint.iacr.org/2016/1114](https://eprint.iacr.org/2016/1114)]{#bib-khati16}
* [TCGALG25 - "TCG Algorithm Registry", Familiy 2.0, Level 00, Revision 01.35, Feb 18, 2025, TrustedComputing
  Group]{#bib-tcgalg25}
* [TCGTPM19A - "Trusted Platform Module Library - Part1: Architecture", Familiy 2.0, Level 00, Revision 01.59, Nov 8,
  2019, Trusted Computing Group]{#bib-tcgtpm19a}
* [TCGTPM19B - "Trusted Platform Module Library - Part2: Structures", Familiy 2.0, Level 00, Revision 01.59, Nov 8,
  2019, Trusted Computing Group]{#bib-tcgtpm19b}
