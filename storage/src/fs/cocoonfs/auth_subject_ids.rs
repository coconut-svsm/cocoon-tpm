// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Definition of [`AuthSubjectDataSuffix`].

/// Authentication subject identifiers
///
/// Appended to HMACced data for indentifying the authenticated data's type and format.
#[repr(u8)]
pub enum AuthSubjectDataSuffix {
    ImageContext = 1,
    AuthTreeRootNode = 2,
    AuthTreeDescendantNode = 3,
    AuthTreeDataBlock = 4,
    EncryptionEntityChainedExtents = 5,
    InodeIndexNode = 6,
    JournalLogField = 7,
}
