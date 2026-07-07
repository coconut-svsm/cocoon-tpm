``` {=html}
<style>
body { max-width: 72em !important; }
</style>
```
# CocoonFs format specification

Copyright 2023-2026 SUSE LLC

Licensed under CC BY-SA 4.0

## [Introduction]{#sec-introduction}
CocoonFs is a special purpose filesystem format designed for securely storing small items of highly sensitive data such
as, but not limited to, a software TPM's state and UEFI variables in a confidential Trusted Execution Environment (TEE)
setting.

In addition to its primary design focus on [strong security properties](#sec-introduction-security), the format
implemens support for some features of particular relevance to the intended use-case, such as support for [keyless
storage volume provisioning](#sec-introduction-online-mkfs) and robustness against service interruptions by means of a
[journal](#sec-introduction-journal). Moreover, in order to enable a wide range of external key retrieval workflows (aka
"remote attestation") at opening time, some free-form [auxiliary metadata](#sec-introduction-aux-fs-metadata) may get
stored with the filesystem. Lastly, for supporting the design of rollback protection protocols, a [filesystem update
counter](#sec-update-counter) cryptographically bound to the filesystem's contents is maintained.

### [Security properties]{#sec-introduction-security}
The most noteworthy features distinguishing CocoonFs from common existing Full Disk Encryption (FDE) solutions designed
primarily for mass storage deployments are:

* The use of fresh, random Initialization Vectors (IV) for each encryption operation.
* Authentication of the filesystem as a whole by means of a Merkle tree.
* The use of subkeys derived from a single (full-entropy) root key for each unique combination of filesystem entity and
  purpose as a means to confine wear-out.

Regarding cryptographic algorithms, the CocoonFs format supports the full set of block cipher and hash algorithms
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

The TEE threat model assumed for CocoonFs deployments is different in that respect though, in that an eavesdropper might
be capable of recording any individual storage write request issued from a TEE. Therefore a fresh, random IV is getting
generated for each encryption operation. Storing those random IVs for individual blocks would be too much overhead,
hence they are associated with logical filesystem entities -- either some metadata structure or a file -- instead. More
specifically, each entity is encrypted with a random IV in Cipher Block Chaining (CBC) mode. This does imply that
partial file updates are not possible, and neither are seeks for reading because of the choice of CBC mode. With the
kind of files anticipated to get typically stored on a CocoonFs target, i.e. small ones, the potential overhead incurred
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
security property point of view, because it yields a single authentication tag binding the state of the CocoonFs
instance as a whole. This enables applications to distribute their state across multiple files while still being
guaranteed a globally coherent view. Note that in particular, that would allow for moving frequently written data, like
a software TPM's current time value, into a dedicated file, thereby avoiding the need to write out the complete, mostly
unchanged state upon each and every update. Furthermore, having a single root authentication digest for the whole
CocoonFs image available might perhaps serve as a basis for interesting future research projects in the area of rollback
protection protocols, c.f. the [filesystem update counter](#sec-update-counter) in this context.

It's expected that the storage backing CocoonFs deployments will typically be relatively small, i.e. that the height of
the Merkle tree will remain within affordable bounds. To get a rough idea on the numbers: five levels with an assumed
node size of 1kB and fanout of 16 would cover 128MB worth of data already. Moreover tree node caches can certainly help
with mitigating the overhead at the read side, as they can get organized such that especially the nodes at the upper
layers will have a good probability of cache residency.

With these considerations, the design choice made for CocoonFs is to accept the additional cost inherent to the Merkle
tree approach in favor of achieving better security guarantees.

As a minor technical detail, note that a few filesystem metadata items still need additional inline authentication tags
for preserving IND-CCA when e.g. finding the location of the authentication tree or reading the journal during
bootstrap, i.e. when opening the filesystem.

#### Key derivation
Some of the data stored on a CocoonFs instance will have low entropy, which might perhaps enable adversaries to acquire
plaintext-ciphertext pairs to conduct a cryptanalysis on. Examples would include e.g. the filesystem metadata
structures, but also certain application files' contents. In order to confine the effects of key wear-out, a unique
subkey is derived from a root key for each combination of filesystem entity and cryptographic purpose. The Key
Derivation Function (KDF) used for that is the `KDFa()` specified in \[[TCGTPM19A](#bib-tcgtpm19a)\].

The initially mentioned algorithm agility support, i.e. the possibility to use any of the algorithms from the TCG
Algorithm Registry \[[TCGALG25](#bib-tcgalg25)\] with CocoonFs, introduces a potential risk of downgrade attacks: by
overwriting algorithms with weak ones in the CocoonFs header, an adversary might perhaps be able to recover some subkey
or even the root key. In order to thwart such attacks, the externally supplied raw root key material, assumed to have
full entropy, is not taken as is, but first run through the `KDFa()` with a fixed hash algorithm, namely SHA-512, with
the other algorithms as found in the image header as additional input.


### Filesystem model
The filesystem model implemented by CocoonFs is a very limited one: there's no directory hierarchy and "file names" are
simply 64 bit integers, i.e. inode numbers.

It is expected that some inode numbers or ranges thereof get statically assigned to a specific application purpose. For
example, when storing a software TPM's state, it would be natural to reserve e.g. the ranges
`0x54504d00_01000000-0x54504d00_01ffffff` for the storage of NV indices and `0x54504d00_81000000-0x54504d00_81ffffff`
for persistent objects, c.f. \[[TCGTPM19B](#bib-tcgtpm19b)\].

Note that for the anticipated CocoonFs usage scenarios, i.e. the storage of core TEE state, it will likely always be
possible to make such static assignments at development time and thus, it is certainly desirable to avoid the overhead
of updating directory metadata structures.

In addition to the data itself, a set of flags is associated with each allocated inode, 8 of which are freely available
for application use.

### [Journal]{#sec-introduction-journal}
For robustness against service interruptions, e.g. power cuts, crashes and alike, CocoonFs implements a journal.

In fact, it is not so much of a journal in the traditional sense as in "a journal with multiple update records": the
CocoonFs journal's capacity is limited to tracking a single pending transaction at a time, where that single transaction
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

### [Auxiliary filesystem metadata]{#sec-introduction-aux-fs-metadata}
In order to enable a wide range of external key retrieval workflows, the filesystem format has support for some
free-form auxiliary filesystem metadata stored as plaintext. The auxiliary filesystem metadata is organized as a
sequence of Tag-Length-Value (TLV) entries, with the tags being 128 bit UUIDS formed according to [RFC
4122](https://datatracker.ietf.org/doc/html/rfc4122). The semantics of any such entry are at the discretion of the party
who generated its respective associated UUID. Implementations are expected to ignore any entries with UUIDs they don't
recognize.

An example use case would be the storage of a wrapped filesystem key, which is to be sent to a remote server for
unwrapping in the course of executing a remote attestation protocol. The designers of that protocol or, alternatively,
anyone building a software architecture integrating the CocoonFs format with that remote attestation protocol, may
generate an UUID for that purpose and define the payload format for storing the wrapped key in a auxiliary filesystem
metatada entry tagged with that UUID.

Typically, the auxiliary filesystem metadata would get initialized at filesystem creation time, and may subsequently get
updated through the regular [journalling](#sec-introduction-journal) mechanism. Updates through the journal, the storage
allocations needed for that in particular, necessarily require access to the filesystem key however. It is anticipated
that some -- perhaps unforseen -- use cases or maintenance workflows may emerge where that requirement would pose a
significant obstacle. Continuing on the example use case from above, that could be a transition to a different remote
attestation server, requiring a rewrap of the filesystem key. To that end, all auxiliary filesystem metadata related
data structures are defined in a way enabling offline updates robust against service interruptions.

### [Confidentiality of allocations and block trimming]{#sec-allocations-confidentiality}
Ideally it should not be possible for an adversary to infer the allocation status of any blocks at any time, because
that would e.g. allow for fingerprinting the TEE's workload.

The metadata tracking the allocations, i.e. the [allocation bitmap](#sec-allocation-bitmap), is encrypted, but in the
assumed TEE threat model of an active adversary able to eavesdrop on IO requests, it is difficult to specify clear,
well-defined security semantics with respect to the confidentiality of the overall allocations state: for example,
whenever a given block is read or written, an adversary observing the IO may readily infer it's allocated at that point
in time.

For that reason, CocoonFs does not define any security guarantees regarding the confidentiality of allocations with
respect to adversaries able to eavesdrop or even alter IO communication.

As a side note: this relaxation is a prerequisite for the support of a dynamically allocated journal: the blocks used
temporarily for the journal can be in any state, therefore their contents cannot get authenticated reliably. More
generally, unallocated block's contents cannot get considered as input for the authentication, only the fact that they
are unallocated can, but this implies that a given block's authentication tag returns to a previous value when
deallocated, something which would otherwise have been highly unlikely.

CocoonFs does however provide optional confidentiality of allocations in the "data at rest model". If enabled, certain
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

However, a TEE should certainly not start to randomly create CocoonFs instances on any attached volumes whose formats it
doesn't recognize and some sort of storage volume tagging mechanism is due. The CocoonFs format implements this by means
of a special [filesystem creation header](#sec-mkfsinfo-header) marking the containing volume as intended for formatting
with a CocoonFs instance at first use in the first place, and specifying all the core configuration parameters required
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
The core CocoonFs metadata structures are:

* The [image header](#sec-image-header) defining filesystem properties, split into an
  [immutable](#sec-static-image-header) and a [mutable](#sec-mutable-image-header) part. The immutable part contains all
  static configuration parameters, the immutable part the changing values such as the authentication tree root digest,
  the filesystem image size etc.
* The [authentication tree](#sec-auth-tree).
* The [allocation bitmap](#sec-allocation-bitmap) tracking the allocation status of each *Allocation Block* in the
  filesystem image.
* The [inode index](#sec-inode-index), organized as a B+-tree.
* The [journal](#sec-journal).

Inodes 0 to 15 (inclusive) are reserved for CocoonFs internal use. The [authentication tree](#sec-auth-tree), the
[allocation bitmap](#sec-allocation-bitmap) and the [inode index](#sec-inode-index) root have entries in the inode index
and are assigned inode numbers 1, 2 and 3 respectively. The [journal log](#sec-journal) and the [filesystem update
counter](#sec-update-counter) have inodes 5 and 6 associated with them respectively, but there's no explicit entry for
either in the inode index -- the numbers are used only for key derivation subject purposes.

For completeness in this context: inode number 0 is reserved for a special "no inode" value, inode number 4 as well as
the range 7-15 (inclusive) are currently not allocated and reserved. Note that the minimum inode index B+-tree leaf node
fill-level is such that inodes 1 to 3 will always be found in the leftmost leaf, which is referred to as the [*inode
index entry leaf node*](#def-inode-index-entry-leaf-node). The location of the inode index entry leaf node is referenced
from the [mutable image header](#sec-mutable-image-header) and enables discovering all the other metadata structures at
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
The CocoonFs format defines two mutually exclusive header types to be placed at the containing storage volume's
beginning:

- In the regular case, after the filesystem has been created on storage and is operational, the [regular CocoonFs
  filesystem header](#sec-filesystem-header) is stored at that location.
- Alternatively, to drive [online filesystem creation](#sec-introduction-online-mkfs) upon first use, a [filesystem
  creation info header](#sec-mkfsinfo-header) may be placed there. It is expected that implementations will conduct the
  filesystem creation upon encountering such one, eventually replacing the header with a [regular CocoonFs
  filesystem header](#sec-filesystem-header) in the course.

Both header types are protected by the [common integrity protection scheme](#sec-extent-integrity). If no valid header
of either type passing integrity verification is found at the storage's beginning when attempting to open a filesystem,
implementations are expected to check for the presence of a filesystem creation info header [backup
copy](#def-mkfsinfo-backup-header) at a specific location determined exclusively from the backing storage volume's
dimensions, and proceed with the online filesystem creation if one is found.

#### [Regular CocoonFs filesystem header]{#sec-filesystem-header}
The regular CocoonFs filesystem image header is split into two parts: a [static](#sec-static-image-header) and a
[mutable](#sec-mutable-image-header) one.  The static image header is located at the beginning of the image, padded to
an integral multiple of the [IO Block](#def-io-block) size so that no neighboring writes will ever alter its
contents. This is important, as the configuration found in the static image header is needed for determining the
filesystem layout and locating the fixed position of the journal log head.

The mutable header is located past the static image header's padding, and changes to it are tracked through the journal,
just as is the case for any update. It contains changing values such as the filesystem image size or the authentication
tree root hash.

##### [Static image header]{#sec-static-image-header}
The static image header starts at offset zero, its format is:

+------------------------------------------------+------------------------------------------------------------------+
|Length in bytes                                 |Description                                                       |
+================================================+==================================================================+
|8                                               |Magic string `'COCOONFS'` (without a terminating zero byte).      |
+------------------------------------------------+------------------------------------------------------------------+
|1                                               |The filesystem format version. Fixed to 0.                        |
+------------------------------------------------+------------------------------------------------------------------+
|21                                              |The set of filesystem image layout parameters, c.f. further below.|
+------------------------------------------------+------------------------------------------------------------------+
|1                                               |The salt length.                                                  |
+------------------------------------------------+------------------------------------------------------------------+
|Length of a [common extent integrity protection |The [integrity protection section](#sec-extent-integrity).        |
|section](#sec-extent-integrity).                |                                                                  |
+------------------------------------------------+------------------------------------------------------------------+
|variable                                        |The salt.                                                         |
+------------------------------------------------+------------------------------------------------------------------+
|variable                                        |Alignment padding.                                                |
+------------------------------------------------+------------------------------------------------------------------+

Some alignment padding up to the next [IO Block](#def-io-block) boundary is inserted at the end of the static image
header. None of the IO Blocks overlapping with the static image header, including that padding, may ever get written to
after the filesystem has been created on storage.

The static image header, including its alignment padding, is subject to the [common extent integrity
protection](#sec-extent-integrity). It is expected that writes to the static image header storage location follow the
[fail-safe extent write protocol](#def-extent-integrity-fail-safe-write). Note that the length of the integrity
protection section is a function of the filesystem image layout parameters. These are located within the [tier 0
integrity protection realm](#sec-extent-integrity-tiers) though, so that their integrity can get verified independently
prior to determine the integrity protection section's total length.

The set of filesystem configuration parameters, referred to as the [*image layout*]{#def-image-layout}, is encoded as
follows:

+-------+-----------------------------------------------------+--------------------------------------------------------+
|Encoded|Name                                                 |Description                                             |
|length |                                                     |                                                        |
|  in   |                                                     |                                                        |
| bytes |                                                     |                                                        |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 1     |`allocation_block_size_128b_log2`                    |Size of an [Allocation Block](#def-allocation-block),   |
|       |                                                     |specified as the base-2 logarithm of the size in units  |
|       |                                                     |of 128B.                                                |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 1     |`io_block_allocation_blocks_log2`                    |Size of an [IO Block](#def-io-block), specified as the  |
|       |                                                     |base-2 logarithm in units of Allocation Blocks. Must be |
|       |                                                     |<= 6.                                                   |
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
| 1     |`index_tree_leaf_node_allocation_blocks_log2`        |Size of an [inode index](#sec-inode-index) B+-tree leaf |
|       |                                                     |node, specified as the base-2 logarithm in units of     |
|       |                                                     |Allocation blocks. Must be <= 6.                        |
+-------+-----------------------------------------------------+--------------------------------------------------------+
| 1     |`index_tree_internal_node_allocation_blocks_log2`    |Size of an [inode index](#sec-inode-index) B+-tree      |
|       |                                                     |internal node, specified as the base-2 logarithm in     |
|       |                                                     |units of Allocation blocks. Must be <= 6.               |
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

##### [Mutable image header]{#sec-mutable-image-header}
The mutable image header is located at the first [IO Block](#def-io-block) aligned boundary following the static image
header. It gets updated through the general journalling mechanics, hence it may be in an inconsistent state at
filesystem opening time.

The mutable image header's format is:

+---------------------------------------+------------------------------------------------------------------------------+
|Length                                 |Description                                                                   |
+=======================================+==============================================================================+
|16B                                    |[Encoded extent pointers](#sec-enc-extent-ptr) to the [auxiliary filesystem   |
|                                       |metadata](#sec-aux-fs-metadata) update groups' head extents.                  |
+---------------------------------------+------------------------------------------------------------------------------+
|Digest length produced by              |The [authentication tree root HMAC digest](#sec-auth-tree-root-digest).       |
|`auth_tree_root_hmac_hash_alg`.        |                                                                              |
+---------------------------------------+------------------------------------------------------------------------------+
|16B aligned upwards to a multiple of   |The encrypted [filesystem update counter](#sec-update-counter).               |
|the [block cipher block                |                                                                              |
|size](#sec-static-image-header)        |                                                                              |
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

##### [Filesystem update counter]{#sec-update-counter}
In order to facilitate the implementation of rollback protection protocols, a *filesystem update counter* is maintained.
It starts at a random offset to be initialized at filesystem creation time, and is incremented modulo $2^{128}$ upon
each update of the filesystem's contents, i.e. upon each update of the [authentication tree](#sec-auth-tree). A remote
ledger would track the minimum update counter ever reported to it and prohibit going back to earlier values. For any
$x$, values in the range $[x + 2^{128}, x - 1] (\textrm{mod} 2^{128})$ are considered to come before $x$.

The filesystem update counter gets serialized in little-endian format, padded with zeros to align to a multiple
of the filesystem's [block cipher block size](#sec-static-image-header) and encrypted

* with a [a subkey derived from the root key](#sec-key-derivation-subkey) with the domain parameter set to 6, i.e. the
  (virtual) inode number allocated to it, a subdomain value of `INODE_KEY_SUBDOMAIN_DATA`, and a key purpose of
  [`KEY_PURPOSE_ENCRYPTION`](#sec-key-derivation),
* in CBC mode with the IV set to all-zeros.

For the choice of a constant all-zeros IV, note that due to the representation in little-endian format, an increment in
the plaintext counter value will affect all blocks in the ciphertext, and, as the counter is strictly monotonic
increasing, the same plaintext wouldn't get encrypted twice.

In order to cryptographically bind the state of the filesystem contents to the update counter, the encrypted filesystem
update counter gets included in the [authentication tree root node digest](#sec-auth-tree-root-digest).

#### [Filesystem creation info header]{#sec-mkfsinfo-header}
As discussed in the introductionary section about [online filesystem creation support](#sec-introduction-online-mkfs),
parties not in possession of the root key may mark a storage volume for formatting with a CocoonFs instance upon first
use by writing a special filesystem creation info header to its beginning. This header provides all the information
required for the actual filesystem creation and is of the following format:

+--------------------------------+------------------------------------------------------------------------------------+
|Length in bytes                 |Description                                                                         |
+================================+====================================================================================+
|8                               |Magic string `'CCFSMKFS'` (without a terminating zero byte).                        |
+--------------------------------+------------------------------------------------------------------------------------+
|1                               |The filesystem creation info header format version. Fixed to 0.                     |
+--------------------------------+------------------------------------------------------------------------------------+
|21                              |The set of filesystem image layout parameters, encoded in the same                  |
|                                |[format](#def-image-layout) as for the regular filesystem header's static part.     |
+--------------------------------+------------------------------------------------------------------------------------+
|8                               |The length of the [auxiliary filesystem metadata](#sec-aux-fs-metadata) payload     |
|                                |[stored alongside](#sec-aux-fs-metadata-mkfsinfo) the filesystem creation info      |
|                                |header, encoded as a 64 bit integer in little-endian format.                        |
+--------------------------------+------------------------------------------------------------------------------------+
|8                               |The desired filesystem image size in units of [Allocation                           |
|                                |Blocks](#def-allocation-block), encoded as a 64 bit integer in little-endian format.|
+--------------------------------+------------------------------------------------------------------------------------+
|1                               |The salt length.                                                                    |
+--------------------------------+------------------------------------------------------------------------------------+
|Length of a [common extent      |The [integrity protection section](#sec-extent-integrity).                          |
|integrity protection            |                                                                                    |
|section](#sec-extent-integrity).|                                                                                    |
+--------------------------------+------------------------------------------------------------------------------------+
|variable                        |The salt.                                                                           |
+--------------------------------+------------------------------------------------------------------------------------+
|variable                        |Alignment padding.                                                                  |
+--------------------------------+------------------------------------------------------------------------------------+

Some alignment padding up to the next [IO Block](#def-io-block) boundary is inserted at the end of the filesystem
creation info header.

The filesystem creation info header, including its alignment padding, is subject to the [common extent integrity
protection](#sec-extent-integrity). It is expected that writes to a fileystem creation info header storage location
follow the [fail-safe extent write protocol](#def-extent-integrity-fail-safe-write). Note that the length of the
integrity protection section is a function of the filesystem image layout parameters. These are located within the [tier
0 integrity protection realm](#sec-extent-integrity-tiers) though, so that their integrity can get verified
independently prior to determine the integrity protection section's total length.

Upon encountering such a filesystem creation header passing the integrity verification at the storage volume's beginning
when attempting to open a filesystem, implementations are supposed to conduct the filesystem creation.

The filesystem creation process inevitably involves a replacement of the filesystem creation info header at the
storage's beginning with the [regular CocoonFs image header](#sec-filesystem-header) at some point. For robustness
against service interruptions encountered during that write, a [backup copy]{#def-mkfsinfo-backup-header} of the former
is made at a specific location on storage beforehand. The location is determined exlusively from the storage volume's
dimensions as follows: find the largest possible power of two not less than the larger of $4\cdot 128\textrm{B}$ and the
[IO Block](#def-io-block) size such that the storage volume accomodates at least $16$ units of that size and place the
backup filesystem creation info header copy at the beginning of the last such. For clarity, the minimum storage volume
size required for supporting online filesystem creation by means of a filesystem creation info header is the larger of
$16\cdot 4\cdot 128\textrm{B} = 8192\textrm{B}$ and $16$ [IO Blocks](#def-io-block). Note that this scheme has been
chosen such that the backup copy will get placed towards the storage volume's end, while still preserving a relatively
large alignment at the same time: having it stored near the end prevents it from intefering with any of the filesystem's
initial metadata structures' placement and the large alignment will enable meaningful error reporting in case the
underlying hardware is not compatible with the selected [IO Block](#def-io-block) size.

In either case, if no valid [image header](#sec-image-header) of either type passing the respective integrity protection
verification is found at the storage volume's beginning when attempting to open a filesystem, neither a [regular
CocoonFs static image header](#sec-static-image-header) nor a filesystem creation info header, then implementations are
expected to check for the presence of a filesystem creation info header backup copy at the specified location. If one is
found, and it passes its integrity verification, then the online filesystem creation procedure is supposed to get
restarted from scratch.

### Integrity protections
Once the CocoonFs image has been opened and the [authentication](#sec-auth-tree) is fully operational, integrity
protection is provided implicitly through the (keyed) authentication. However, some core filesystem entities like the
[image header](#sec-static-image-header) must get examined in the course of the bootstrapping procedure itself, and
therefore have dedicated integrity protections in place.

The CocoonFs format defines two mechanisms for integrity protections: a bare [checksum scheme](#sec-crc) and, as
checksums are inherently prone to collisions, a common [extent protection scheme](#sec-extent-integrity) designed to
provide additional robustness against torn writes for certain extent types subject to this protection.

#### Checksum scheme{#sec-crc}
The checksum is formed by concatenating a pair of two CRC-32 values: one over the plain data, and another one over the
same data but with the bits at odd and even positions swapped. The rationale follows below.

The CRC polynomial used in either case is the standard CRC-32 one, with a corresponding 32 bit integer representation of
`0x04c11db71`, where the arithmetically most significant bit specifies the coefficient to the term of degree $31$, and
the least signigicant bit the constant term. A string of $32$ $1$-bits is prepended to the data before the CRC
computation starts. Successive bytes in the data correspond to terms of decreasing degree in the to be reduced data
polynomial, and within each byte, bits of decreasing arithmetic significance correspond to terms of increasing
polynomial degree. The final residual polynomial's coefficient are inverted and serialized with the same association
between polynomial terms and bits on storage as just described for the data.

##### Rationale
In principle, it would have been possible to (re)use some cryptographic hash function needed for the authentication
anyway to also provide integrity protection in these contexts. However, there might be use-cases where an implementation
would examine (and possibly even alter) only the filesystem metadata, but not attempt to run a full filesystem opening
procedure. If cryptographic hashes were used for the integrity protections, such implementations would have to implement
support for any such algorithm possibly to be encountered -- something which external policies and regulations might
prohibit. For this reason, a dedicated checksumming scheme is used instead, which should be unproblematic and
universally available. The checksum scheme used to provide integrity protections for CocoonFs is based on the well-known
Cyclic Redundancy Checksum (CRC) class of checksums.

The features of a particular CRC instance, most notably the checksum length, are determined exclusively by the chosen
CRC polynomial. The most commonly used ones are either $32$ or $64$ bits in length. In general, longer
polynomials/checksums provide better protection, obviously. More specifically, CRCs computed over uniformly distributed
data are again uniform and in this idealized case, the probability of not detecting random errors is either $1:2^{32}$
or $1:2^{64}$, depending on whether the chosen CRC polynomial is of degree $32$ or $64$.  One of the checksums'
primary purposes in the context of CocoonFs is to detect incomplete writes issued from an interrupted filesystem
creation operation -- the only point in time the [static image header](#sec-static-image-header) is getting actively
written to. A chance of $1:2^{32}$ for missing header corruptions may well be considered too unreliable, and a $64$ bit
checksum should be used instead.

However, CRC polynomials of larger degree tend to be more demanding in terms of runtime resources, e.g. of internal
lookup tables' sizes. Moreover, implementations for the widely adopted standard CRC-32 polynomial are more generally
available, both for hard- and software. Therefore, a hybrid approach yielding a $64$ bit checksum of the desired
properties exclusively from the CRC-32 primitive has been chosen for CocoonFs. The checksum is formed from a pair of two
CRC-32 values: one over the protected data, and another one over that same data, but with the bits at odd and even
positions swapped each.

##### Checksum properties
The CRC-32 polynomial is irreducible, hence the ring of its residue classes forms a field. Therefore,
the following two are equivalent in the sense that one uniquely determines the other:

* the pair of CRC-32 values computed as described above to form the checksum, i.e. one over the plain data and another
  one over the data with the bits at odd and even positions swapped,
* a pair of CRC-32 values, one computed exclusively from the bits at odd positions, and the other one exclusively from
  the bits at even positions.

In particular, the chance of missing a random data corruption is $1:2^{64}$.

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

#### [Common extent integrity protection scheme]{#sec-extent-integrity}
The common extent integrity protection scheme only applies to certain [extent](#def-extent) types whose boundaries are
aligned to multiples of a [filesystem IO Block](#def-io-block) on storage. It transforms the protected extent's contents
-- conceptually the integrity protections are applied last after encoding any of the higher-level data structures and
right before writing the extent to storage. Conversely, the integrity protections are removed again and the contents
restored to their original state right after reading the protected extent from storage and before decoding any of the
higher-level data structures.

For what follows, the backing hardware device's minimum IO granularity is referred to a a [*device IO
Block*]{#def-dev-io-block}. A [device IO Block](#def-dev-io-block) is never larger than the [filesystem's IO
Block](#def-io-block) size attribute, as per the definition of the latter. In particular, a write to one [device IO
Block](#def-dev-io-block) is assumed to never affect the contents of any other [device IO Block](#def-dev-io-block), at
any stage of the write.

For the purpose of the discussion that follows, the [extent](#def-extent) is split into two logical parts:

- its first [device IO Block](#def-dev-io-block)
- and its tail remainder.

Implementations are expected to proceed according to the following [*fail-safe extent write
protocol*]{#def-extent-integrity-fail-safe-write} when updating an integrity protected extent on storage, semantically
equivalent behavior is permitted.

1. Invalidate the extent's first [device IO Block](#def-dev-io-block) on storage by writing all-zeros to it.
2. Issue a write barrier.
3. Update the extent's tail on storage, if any.
4. If the tail is non-trivial, issue a write barrier.
5. Update the extent's first [device IO Block](#def-dev-io-block) on storage.

The semantics of the write barrier must be such that any writes issued after it must not become effective on storage,
not even partially, before any writes prior to it have become fully effective.

To handle service interruptions encountered during the final write of the extent's first [device IO
Block](#def-dev-io-block), integrity protections are applied to the first [filesystem IO Block](#def-io-block) (which
always contains the first [device IO Block](#def-dev-io-block)). In general, the contents of a
[device IO Block](#def-dev-io-block) following a service interruption encountered during a write, aka a "torn write",
can be in any state. Note that in practice however, hardware typically exhibits either of two behaviors, sometimes
implemented only as a "best-effort" guarantee: the data is either all-old or all-new, or alternatively, there's a pivot
point somewhere within the [device IO Block](#def-dev-io-block) partitioning it into an all-old and an all-new region
each. Observe that the former behavior is a special case of the latter.

Two complementary integrity protection mechanisms are applied to the first [filesystem IO Block](#def-io-block):

* common [checksum](#sec-crc) protection and,
* to improve reliability on devices implementing the typical "old-new" [device IO Block](#def-dev-io-block) partitioning
  behavior on torn writes as described above, special write completion marker values are written to certain checkpoint
  locations within the extent's first [filesystem IO Block](#def-io-block).

Due do the possibility of collisions, the checksum based protection scheme might fail to detect corruptions, even though
the probability of $1:2^{64}$ of that happening is generally considered to be negligible in practice. The write
completion marker based mechanism is guaranteed to always detect partial writes reliably on hardware implementing the
common "old-new" partitioning behavior on torn writes.

An extent's integrity protection data section format is an invariant of the filesystem, the [filesystem IO
Block](#def-io-block) size to be more specific, and organized as follows:

+-------------------------------------------------------+---------------------------------------+
|Length                                                 |Description                            |
+-------------------------------------------------------+---------------------------------------+
|8                                                      |Commit ID, derived from the checksum.  |
+-------------------------------------------------------+---------------------------------------+
|1                                                      |XOR mask.                              |
+-------------------------------------------------------+---------------------------------------+
|$8\cdot(\texttt{io\_block\_allocation\_blocks\_log2} + |Checkpoint locations data save area.   |
|\texttt{allocation\_block\_size\_128b\_log2})$         |                                       |
+-------------------------------------------------------+---------------------------------------+

Observe that the checkpoint locations data save area's length is given by the base-2 logarithm of the [filesystem IO
Block](#def-io-block) size in units of $128\textrm{B}$, mutiplied by the [checksum](#sec-crc) length.

The offset at which integrity protection data section is stored within an extent depends on the extent type, with the
constraint that its first $(8 + 1)\textrm{B}$ always are located within the extent's first $128\textrm{B}$. That is the
offset is always $\leq $128\textrm{B} - (8 + 1)\textrm{B}$.

The [checksum](#sec-crc) is computed over all of the extent's original data, before any of the write completion markers
have been written to it. For the purpose of the checksum computation, all of the extent's integrity protection data
section is set to zero.

The write completion marker based mechanism is divided into two [tiers]{#sec-extent-integrity-tiers}: tier 0 protects
the first $128\textrm{B}$, tier 1 the first [filesystem IO Block's](#def-io-block) remainder. Tier 1 may reach into the
tier 0 region and is described first.

The *commit ID* value is derived from the [checksum](#sec-crc) as described further below and gets written as a write
completion marker to certain checkpoint locations withing the first [filesystem IO Block](#def-io-block):

* once to its designated slot within the extent's integrity protection data section,
* to every possible [device IO Block](#def-dev-io-block) end for any [device IO Block](#def-dev-io-block) larger than
  $128\textrm{B}$. That is, right before any power-of-two boundary within the containing [filesystem IO
  Block](#def-io-block), starting at $256\textrm{B}$.

The data originally found at the respective checkpoint locations $>128\textrm{B}$ gets copied back-to-back to a
*checkpoint locations data save area* within the extent's integrity protection data section before overwriting it with
the write completion marker value respectively. For definiteness in case the checkpoint locations data save area
contains a checkpoint location itself (which is possible only for an unreasonably large [filesystem IO
Block](#def-io-block) size): the copying is supposed to be done in order from the highest checkpoint location to lowest.

If at filesystem opening time the values found at these checkpoint locations are not all equal, then the extent is
considered to have been written only partially and is dismissed. Observe that, under the assumed torn write hardware
behavior, the write completion markers protect any of of the data region spanning from the beginning of the extent's
integrity protection data section all the way to the end of the first [filesystem IO Block](#def-io-block), i.e. any
data at offset $\geq 128\textrm{B}$ in particular.

To cover the range $\lt 128\textrm{B}$, the extent's first $128\textrm{B}$ are XOR-masked with a byte value chosen such
that the results are all non-zero, possibly skipping over some of its leading bytes storing an extent type dependent
magic. If any of the bytes in this $128\textrm{B}$ range are found to equal zero at verification time, then the extent
is considered to have been written only partially and is dismissed.

For clarity, the XOR-mask is chosen and applied

- after the original data from the checkpoint locations at offsets $>128\textrm{B}$ has been opied over to the
  checkpoint locations data save area and
- before the commit ID and the XOR-mask value get stored at their respective locations within the extent's integrity
  protection data section. For the purpose of selecting the XOR-mask value, these locations may be assumed to be
  identical to zero.

The commit ID is defined to equal the [checksum](#sec-crc) with the XOR-mask applied and stored as such at offset $0$
within the extent's integrity protection data section, and is therefore contained within the extent's first
$128\textrm{B}$. The XOR-mask byte value itself is stored at offset $8$ within the extent's integrity protection data
section, therefore is contained within the first $128\textrm{B}$ as well. As both are contained within the first
$128\textrm{B}$, they must not contain any zero bytes. That is, the XOR-mask byte value must be chosen under the
additional constraint that it's non-zero and different from any of the bytes in the [checksum](#sec-crc).

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
* A pair of a 64 bit and a 32 bit integer, specifying a "domain" and "subdomain".

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
* `context` - The concatenation of the input "domain" and "subdomain" values, encoded as 64 and 32 bit integers in
  little-endian format respectively.
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
   [image header](#sec-image-header), the [journal log head](#sec-journal-log-encryption) or any of the [auxiliary
   filesystem metadata extents](#sec-aux-fs-metadata-formatted),
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

### [Authentication tree root node digest]{#sec-auth-tree-root-digest}
The authentication tree root digest is created by computing a HMAC with an underlying hash of
[`auth_tree_root_hmac_hash_alg`](#def-image-layout) and a [a subkey derived from the root
key](#sec-key-derivation-subkey) with the domain parameter set to 1, i.e. the authentication tree's associated inode
number, a subdomain value of 0, and a key purpose of [`KEY_PURPOSE_AUTH_ROOT`](#sec-key-derivation) over

1. the digests stored in the root node back to back
2. and an [authentication context](#sec-auth-context) formed as follows:
   1. The index in the [Authentication Tree Data Block index domain](#def-auth-tree-data-block-index-domain) of the root
      node's last entry's associated data region's beginning modulo $2^{64}$, encoded as a 64 bit integer in
      little-endian format. Observe that this uniquely fixes the position of the root node in the tree.
   2. The encrypted [filesystem update counter](#sec-update-counter).
   3. The "image context", a digest over filesystem configuration parameters computed as described below.
   4. An authentication context format version identifier byte of constant 0.
   5. An authentication context subject identifier byte of constant
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
Inodes are identified by positive 64 bit integers. The inode index tracks the allocated inodes and a set of associated
flags as well as the locations of inode data on storage each. The inode flags are stored as 32 bit integers in
little-endian format, of which the least significant 8 bits are freely available for application use, and the remaining
24 bits are reserved and constant zero. The location of each inode's data on storage is represented either by means of a
direct [encoded extent pointer](#sec-enc-extent-ptr) or by an "indirect" pointer pointing to the head of some [chained
extents](#sec-encryption-entity-chained-extents) storing the inode's [extents list](#sec-enc-extents-list).

The inode index is organized as a B+-tree, with node sizes as specified by the
[`index_tree_leaf_node_allocation_blocks_log2`](#def-image-layout) and
[`index_tree_internal_node_allocation_blocks_log2`](#def-image-layout) filesystem configuration parameters respectively.

The minimum leaf node fill level is constrained to be >= 3, so that inodes 1-3 are always found in the leftmost leaf
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
Let $B_{\textrm{leaf}}$ denote a decrypted index leaf node's maximum possible payload size in units of bytes. The
maximum number of entries in a leaf node is then given by
$M_{\textrm{leaf}} = \left\lfloor\frac{B_{\textrm{leaf}} - 12}{20}\right\rfloor$.
The minimum leaf node fill level is set to $m_\textrm{leaf} = \left\lceil\frac{M_\textrm{leaf}}{2}\right\rceil$.
$B_{\textrm{leaf}}$ must be large enough so that the constraint $m_\textrm{leaf} >= 3$ holds. Note that with a minimum
inode index leaf node block size of 128B, and a maximum IV length of 16B, the $m_\textrm{leaf} >= 3$ is automatically
fulfilled.

The leaf node format is as follows:

+---------------------------------------------------------------+------------------------------------------------------+
|Range in units of bytes                                        |Description                                           |
+===============================================================+======================================================+
|$0$ to $8$                                                     |[Encoded block pointer](#sec-enc-block-ptr) to the    |
|                                                               |next leaf node in tree order, if any, or NIL          |
|                                                               |otherwise.                                            |
+---------------------------------------------------------------+------------------------------------------------------+
|$8$ to $8 + 8\cdot M_\textrm{leaf}$                            |The inode entries' associated [encoded extent         |
|                                                               |pointers](#sec-enc-extent-ptr).                       |
+---------------------------------------------------------------+------------------------------------------------------+
|$8 + 8\cdot M_\textrm{leaf}$ to $8 + 16\cdot M_\textrm{leaf}$  |The inode entries' associated keys, i.e. the inode    |
|                                                               |numbers, encoded as 64 bit integers in little endian  |
|                                                               |format.                                               |
+---------------------------------------------------------------+------------------------------------------------------+
|$8 + 16\cdot M_\textrm{leaf}$ to $8 + 20\cdot M_\textrm{leaf}$ |The inode entries' associated flags, encoded as 32 bit|
|                                                               |integers in little-endian format.                     |
+---------------------------------------------------------------+------------------------------------------------------+
|$8 + 20\cdot M_\textrm{leaf}$ to $12 + 20\cdot M_\textrm{leaf}$|The node level, fixed to 1 for leaf nodes, encoded as |
|                                                               |a 32 bit integer in little-endian format.             |
+---------------------------------------------------------------+------------------------------------------------------+

For $i\in\{0\ldots M_\textrm{leaf} - 1\}$, the i'th inode flags entry and i'th [encoded extent
pointer](#sec-enc-extent-ptr) are associated with the i'th key respectively. Unoccupied entries have a key value of 0,
i.e. the special "no inode" value, the inode flags all unset and an encoded extent pointer value of NIL. The unoccupied
slots must all be at the tail. The occupied entries must be sorted by the inode number. No leaf node with less than
$m_\textrm{leaf}$ nodes may exist, except for possibly at the tree root.

### Inode index internal node format
Let $B_{\textrm{internal}}$ denote a decrypted index internal node's maximum possible payload size in units of
bytes. The maximum number of entries, i.e. separating keys, in an internal node is then given by
$M_{\textrm{internal}} = \left\lfloor\frac{B_{\textrm{internal}} - 12}{12}\right\rfloor$.
The minimum internal node fill level is set to
$m_\textrm{internal} = \left\lfloor\frac{M_\textrm{internal} - 1}{2}\right\rfloor$. $B_{\textrm{internal}}$ must be
large enough so that the constraint $m_\textrm{leaf} >= 1$ holds. Note that with a minimum inode index internal node
block size of 128B, and a maximum IV length of 16B, the $m_\textrm{internal} >= 1$ is automatically fulfilled.

Implementations might want to preemptively split full nodes or merge pairs of nodes at minimum fill level when walking
down a path from the root for insertion or deletion.Note that $m_\textrm{internal}$ has been defined specifically in a
way to enable preemptive splitting of full nodes as well as merging nodes at the minimum fill level, even for even
values of $M_\textrm{internal}$.

+-----------------------------------------------------------------------+----------------------------------------------+
|Range in units of bytes                                                |Description                                   |
+=======================================================================+==============================================+
|$0$ to $8 + 8\cdot M_\textrm{internal}$                                |[Encoded block pointers](#sec-enc-block-ptr)  |
|                                                                       |to the node's children.                       |
+-----------------------------------------------------------------------+----------------------------------------------+
|$8 + 8\cdot M_\textrm{internal}$ to $8 + 12\cdot M_\textrm{internal}$  |The separator keys, encoded as 64 bit integers|
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
   [`index_tree_leaf_node_allocation_blocks_log2`](#def-image-layout)
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

1. The inode number as a 64 bit integer, encoded in little-endian format.
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

### [Journal log encryption]{#sec-journal-log-encryption}
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

### [Journal log head extent plaintext header](#sec-journal-log-head-plaintext-header)
The [encrypted chained extents](#sec-encryption-entity-chained-extents) encryption entity format allows for a plaintext
header to get stored in the first head extent. For the journal log, this plaintext header comprises

* a magic of `CCFSJRNL`, without a terminating zero byte, if the journal is to be considered active,
* an [extent integrity protection section](#sec-extent-integrity) for detecting torn writes to the head extent,
* a pair of two [encoded extent pointers](#sec-enc-extent-ptr) to the auxiliary filesystem metadata update groups' head
  extents.

Note that updates of the journal log head extent on storage must follow the [fail-safe extent write
protocol](#def-extent-integrity-fail-safe-write), as is the case for any extent subject to the [common integrity
protection scheme](#sec-extent-integrity).

The journal is to be considered non-empty and to get applied upon the next filesystem opening following a possible
service interruption whenever its head extent begins with a magic of `'CCFSJRNL'`, without a terminating zero byte, and
the head [extent's integrity protections](#sec-extent-integrity) can get successfully verified. The magic is exempt from
the [extent integrity protection's](#sec-extent-integrity) transformations.

### [Journal log payload contents]{#sec-journal-log-payload-contents}
The journal log payload, subject to encryption in the [encrypted chained
extents](#sec-encryption-entity-chained-extents) format, is organized as sequence of tag-length-value (TLV) encoded
fields. The tag and length are encoded as unsigned integers in LEB128 format, the format of the value depends on the
field. The fields must be stored in the journal in the order induced by increasing tag values. The defined tag values
are:

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

#### Allocation bitmap file fragments' authentication digests
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
	  
#### [Writes application script]{#sec-journal-apply-writes-script-script}
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

#### [Authentication tree update script]{#sec-journal-auth-tree-updates-script}
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

#### Trim script
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

## [Auxiliary filesystem metadata]{#sec-aux-fs-metadata}
The [auxiliary filesystem metadata](#sec-introduction-aux-fs-metadata) payload is
[encoded](#sec-aux-fs-metadata-encoding) as a sequence of TLV records, and stored either as a contiguous blob next to a
[filesystem creation info header](#sec-mkfsinfo-header) or, once the filesystem has been created, distributed across one
or more [extents](#def-extent).

### [Payload encoding]{#sec-aux-fs-metadata-encoding}
The auxiliary fileystem metadata is encoded as a sequence of records, each in format as follows:

+----------------+-----------------------------------------------------------------------------------------+
|Length in bytes |Description                                                                              |
+================+=========================================================================================+
|16              |The tag, i.e. a [RFC 4122](https://datatracker.ietf.org/doc/html/rfc4122) UUID.          |
+----------------+-----------------------------------------------------------------------------------------+
|4               |Length of the data portion in bytes, encoded as a 32 bit integer in little-endian format.|
+----------------+-----------------------------------------------------------------------------------------+
|variable        |The entry's associated data.                                                             |
+----------------+-----------------------------------------------------------------------------------------+

The sequence ends with a special termination record with an UUID of all-zeros. The termination record's data length is
either 0B or 8B. In the latter case its data portion contains a 64 bit integer encoded in little-endian format,
specifying the [extra reserve capacity](#def-aux-fs-metadata-extra-reserve-capacity) to be defined further below.

All of the sequence's entries up to the final termination record must be in order of lexically increasing UUIDs.
Multiple entries with the same UUID may exist as far as the filesystem format itself is concerned.


### [Storage as part of the filesystem creation info data]{#sec-aux-fs-metadata-mkfsinfo}
Some initial auxiliary filesystem metadata to write at [online filesystem creation](#sec-introduction-online-mkfs) may
get stored alongside a [filesystem creation info header](#sec-mkfsinfo-header). Remember that a [filesystem creation
info header](#sec-mkfsinfo-header) is either found at the storage volume's beginning, or, in case of a [backup
copy](#def-mkfsinfo-backup-header), towards its end at a location determined exclusively
from the storage dimensions. The auxiliary filesystem metatdata, if any, is encapsulated as described below and stored
as a contiguous blob

- right after the [filesystem creation info header](#sec-mkfsinfo-header) if that is located at the storage volume's
  beginning, or
- right in front [filesystem creation info header](#sec-mkfsinfo-header) in case of the backup location.

The length of the [plain encoded](#sec-aux-fs-metadata-encoding) auxiliary filesystem metadata payload is recorded in
one of the [filesystem creation info header](#sec-mkfsinfo-header) fields, allowing for determining its storage location
once the [filesystem creation info header](#sec-mkfsinfo-header) has been found and read. As a special case, if that
value is specified as $0$, then there is no auxiliary filesystem metadata stored alongside the [filesystem creation info
header](#sec-mkfsinfo-header).

The encapsulation format is organized as follows:

+----------------+-------------------------------------------------------------------------------------------+
|Length in bytes |                                                                                           |
+================+===========================================================================================+
|8               |[Checksum](#sec-crc) over the data, including the alignment padding.                       |
+----------------+-------------------------------------------------------------------------------------------+
|variable        |The [encoded auxiliary filesystem metadata payload](#sec-aux-fs-metadata-encoding).        |
+----------------+-------------------------------------------------------------------------------------------+
|variable        |Padding to align the total length to the [IO Block](#def-io-block) size. Must be all-zeros.|
+----------------+-------------------------------------------------------------------------------------------+

It is expected that if a [filesystem creation info header](#sec-mkfsinfo-header) passes the [integrity
protection](#sec-extent-integrity) validation, i.e. has not suffered from torn writes in particular, then the auxiliary
filesystem metadata stored alongside it would be valid as well. In practice that means that the auxiliary filesystem
metadata needs to get written before the header, with a write barrier issued inbetween.

Note that the [filesystem creation info header](#sec-mkfsinfo-header) backup scheme naturally lends itself to a
fail-safe A/B type update strategy for the auxiliary filesystem metadata. For example, suppose that the filesystem
creation info data, i.e. the [filesystem creation info header](#sec-mkfsinfo-header) and the auxiliary filesystem
metadata stored alongside it are initially found at the primary location, i.e. at the storage volume's beginning. Then

1. Make a backup copy, i.e.
   a. Invalidate the [filesystem creation info header](#sec-mkfsinfo-header) [integrity
      protections](#sec-extent-integrity) at the backup location by writing all-zeros. Note that this needs to be done
      independent of whether a valid header is already stored at the backup location -- no header at this location may
      be considered effective until after the auxiliary filesystem metadata has been written in full below.
   b. Issue a write barrier.
   c. Write the original auxiliary filesystem metadata to the backup location.
   d. Issue a write barrier.
   e. Write the original [filesystem creation info header](#sec-mkfsinfo-header) to the backup location, following the
      [fail-safe extent write protocol](#def-extent-integrity-fail-safe-write), as is required for any [filesystem
      creation info header](#sec-mkfsinfo-header) write.
2. Update the primary location, i.e.
   a. Invalidate the [filesystem creation info header](#sec-mkfsinfo-header) [integrity
      protections](#sec-extent-integrity) at the primary location by writing all-zeros.
   b. Issue a write barrier.
   c. Write the updated auxiliary filesystem metadata to the primary location.
   d. Issue a write barrier.
   e. Write the updated [filesystem creation info header](#sec-mkfsinfo-header) to the primary location, following the
      [fail-safe extent write protocol](#def-extent-integrity-fail-safe-write), as is required for any [filesystem
      creation info header](#sec-mkfsinfo-header) write.
3. Optionally, invalidate the [filesystem creation info header](#sec-mkfsinfo-header) at the backup location.

### [Storage in a formatted filesystem]{#sec-aux-fs-metadata-formatted}
Once the filesystem has been created, the auxiliary filesystem metadata is stored across a sequence of
[extents](#def-extent) chained in a certain way and referenced from the [mutable image
header](#sec-mutable-image-header) as well as from the [journal log head extent's plaintext
header](#sec-journal-log-head-plaintext-header), if active.

The auxililary filesystem metadata is stored in a format designed for enabling offline updates, i.e. when the filesystem
key is unavailable, while still preserving full robustness guarantees against service interruptions encountered during
storage writes. Details follow.

The extents are tracked as allocated in the [allocation bitmap](#sec-allocation-bitmap), but considered unallocated for
the purpose of computing [authentication tree data block digests](sec-auth-tree-data-block-digest). All extents'
boundaries must be aligned to the larger of the [IO Block](#def-io-block) and the [Authentication Tree Data
Block](#def-auth-tree-data-block) size. Note that the extents are constrained to be aligned to the [Authentication Tree
Data Block](#def-auth-tree-data-block) size only for the convenience of implementations: for the purpose of computing
[authentication tree data block digests](sec-auth-tree-data-block-digest), the auxililary filesystem metadata extents
are to be considered as if unallocated as a special case, and letting them occupy an integral multiple of the
[Authentication Tree Data Block](#def-auth-tree-data-block) size alleviates the need to implement range checks for
detecting this special case when updating potentially neighboring data.

The auxiliary filesystem metadata extents collectively form a directed, circular linked list, partitioned into either
one or two [*update groups*]{#def-aux-fs-metadata-update-group}. The [mutable image header](#sec-mutable-image-header)
as well as the [journal log head extent's plaintext header](#sec-journal-log-head-plaintext-header) contain a pair of
[encoded extent pointers](#sec-enc-extent-ptr) to the update groups' respective head extents each. The pointer pair's
first entry may be NIL only if the second is as well. If the first entry is NIL, then there is no auxiliary filesystem
metadata stored in the filesystem. The update group pointed to the by the pointer pair's first entry is referred to as
*update group 0*, the one pointed to by the second entry, if any, as *update group 1*. If there is no update group 1,
then no offline updates are possible. If a journal log is active, the pointer pair found therein takes precedence over
that from the [mutable image header](#sec-mutable-image-header). In fact, whenever a journal log is active, no
assumptions must be made about the validity of the [mutable image header's](#sec-mutable-image-header) contents on
storage.

Any extent in the circular linked list contains [encoded extent pointers](#sec-enc-extent-ptr) to the next and next but
one extent in the list and is subject to the common [extent integrity protection scheme](#sec-extent-integrity). The
[update groups'](#def-aux-fs-metadata-update-group) head extents contain an additional boolean flag specifying whether
the group is active or not. Altogether, the auxiliary filesystem metadata extent format is:

+------------------------------------------+---------------------------------------------------------------------------+
|Length in bytes                           |Description                                                                |
+==========================================+===========================================================================+
|8                                         |[Encoded extent pointer](#sec-enc-extent-ptr) to the next extent in the    |
|                                          |circular list.                                                             |
+------------------------------------------+---------------------------------------------------------------------------+
|8                                         |[Encoded extent pointer](#sec-enc-extent-ptr) to the next but one extent in|
|                                          |the circular list.                                                         |
+------------------------------------------+---------------------------------------------------------------------------+
|1                                         |[Update group](#def-aux-fs-metadata-update-group) active/inactive          |
|                                          |state. Present only in [update group](#def-aux-fs-metadata-update-group)    |
|                                          |head extents.                                                              |
+------------------------------------------+---------------------------------------------------------------------------+
|Length of a [common extent integrity      |The [integrity protection section](#sec-extent-integrity).                 |
|protection section](#sec-extent-integrity)|                                                                           |
+------------------------------------------+---------------------------------------------------------------------------+
|Extent remainder                          |[Encoded auxiliary filesystem metadata](#sec-aux-fs-metadata-encoding)     |
|                                          |payload part.                                                              |
+------------------------------------------+---------------------------------------------------------------------------+

For clarity, the pointers to the subsequent extents are never NIL, as the circular list is considered to repeat itself.

As it's the case with any extent subject to the [common extent integrity protection scheme](#sec-extent-integrity),
updates to an auxiliary filesystem metadata extent must follow the [fail-safe extent write
protocol](#def-extent-integrity-fail-safe-write). The pointers to the next and next but one extents, and, for [update
group](#def-aux-fs-metadata-update-group) heads, the active/inactive state as well, are located in the [tier 0 integrity
protection realm](#sec-extent-integrity-tiers). They must have correct values whenever the tier 0 integrity protection
would validate. At most one extent in the circular chain may fail the [integrity protection](#sec-extent-integrity)
validation at any point in time, and only if an [update group 1](#def-aux-fs-metadata-update-group) is present. Observe
how these constraints guarantee that the complete list of extents as such can always get reconstructed, even if one of
them suffered from a torn write. Note that this is crucial not only in the context of the auxiliary filesystem metadata
itself, but also for the ability to maintain the [authentication tree](#sec-auth-tree), especially when [reconstructing
it during journal replay](#sec-journal-auth-tree-updates-script), due to the auxiliary filesystem metadata extents being
tracked as allocated in the [allocation bitmap](#sec-allocation-bitmap), but considered unallocated for the purpose of
computing [authentication tree data block digests](sec-auth-tree-data-block-digest), as specified above.

An [update group](#def-aux-fs-metadata-update-group) can be either in active or inactive state, as determined from the
active/inactive state field stored in its head extent. The possible values are

+---------------------------------------------------------------+-----+-----------------------------------------+
|Name                                                           |Value|Description                              |
+===============================================================+=====+=========================================+
|`AUX_FS_METADATA_UPDATE_GROUP_STATE_INACTIVE`                  |0    |The [update                              |
|                                                               |     |group](#def-aux-fs-metadata-update_group)|
|                                                               |     |is inactive.                             |
+---------------------------------------------------------------+-----+-----------------------------------------+
|`AUX_FS_METADATA_UPDATE_GROUP_STATE_ACTIVE`                    |1    |The [update                              |
|                                                               |     |group](#def-aux-fs-metadata-update-group)|
|                                                               |     |is active.                               |
+---------------------------------------------------------------+-----+-----------------------------------------+
|`AUX_FS_METADATA_UPDATE_GROUP_STATE_ACTIVE_REALLOCATION_NEEDED`|2    |The [update                              |
|                                                               |     |group](#def-aux-fs-metadata-update-group)|
|                                                               |     |is active. A hint to conduct a           |
|                                                               |     |reallocation of its backing storage once |
|                                                               |     |possible has been set.                   |
+---------------------------------------------------------------+-----+-----------------------------------------+

If active, all of the group's constituent extents are expected to be collectively coherent, and the concatenated payload
contents to form a valid [auxiliary filesystem metadata encoding](#sec-aux-fs-metadata-encoding). In particular, all of
the group's constituent extents are expected to pass their respective [integrity protection](#sec-extent-integrity)
validation. At least one [update group](#def-aux-fs-metadata-update-group) must be active at any given point in time. If
both are active, [update group 0](#def-aux-fs-metadata-update-group) takes precedence, i.e. the auxiliary filesystem
metadata contents stored therein are considered effective.

Assuming that [update group 0](#def-aux-fs-metadata-update-group) is initially active, an offline auxiliary filesystem
metatdata update could be implemented as follows, with all the individual extent storage writes adhering to the
[fail-safe extent write protocol](#def-extent-integrity-fail-safe-write):

1. If there is some extent failing [integrity protection](#sec-extent-integrity) validation (necessarily in an inactive
   group, i.e. group 1), repair it.
2. If update group 1 is active, deactivate it by updating its head extent accordingly.
3. Copy the original auxiliary filesystem metadata to update group 1 and activate it.
   a. Write the tail extents, if any first.
   b. Write the head extent in a final step, set the active flag.
4. Update group 0 with the updated auxiliary filesystem metadata contents.
   a. Write the tail extents, if any first.
   b. Write the head extent in a final step, set the active flag.

Of course, this assumes that there is an [update group 1](#def-aux-fs-metadata-update-group) in the first place, and
that both [update groups](#def-aux-fs-metadata-update-group) have a sufficient payload storage capacity each. That is,
preparations need to be made ahead of time at auxiliary filesystem metatdata extents allocation in order to enable
offline updates. Whether to allocate an [update group 1](#def-aux-fs-metadata-update-group) and the amount of excess
space to allocate in both [update groups](#def-aux-fs-metadata-update-group) depends on policy and is outside the scope
of this specification. In order to guide any auxiliary filesystem metatdata extents (re)allocation, the [*extra reserve
capacity*]{#def-aux-fs-metadata-extra-reserve-capacity} property may be defined. The extra reserve capacity property
value, if any, is stored as part of the [auxiliary filesystem metadata encoding's](#sec-aux-fs-metadata-encoding)
termination record. The termination record's encoding length determines whether an extra reserve capacity value is
defined or not. If it is not defined, then no [update group 1](#def-aux-fs-metadata-update-group) shall be allocated at
any subsequent extents (re)allocation. Otherwise an [update group 1](#def-aux-fs-metadata-update-group) will get
allocated and the extra reserve capacity specifies the amount of additional payload space in units of bytes to allocate
in both [update groups](#def-aux-fs-metadata-update-group) over the minimum required to store the auxiliary filesystem
metadata contents defined at that time.

When drawing from the [extra reserve capacity](#def-aux-fs-metadata-extra-reserve-capacity), offline updates may set the
[update group's](#def-aux-fs-metadata-update-group) head extent's active/inactive state field to
`AUX_FS_METADATA_UPDATE_GROUP_STATE_ACTIVE_REALLOCATION_NEEDED` in order to signal that a reallocation would be desired
once possible for reestablishing [extra reserve capacity](#def-aux-fs-metadata-extra-reserve-capacity) excess
allocation.

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
    is defined so that inodes 1-3 will always be found in that node.
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
