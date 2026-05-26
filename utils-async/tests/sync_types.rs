// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Red Hat, LLC
// Author: Oliver Steffen <osteffen@redhat.com>

mod sync_types {
    mod deref_inner_by_tag;
    mod generic_arc;
    mod generic_sync_rc_ptr_ref;
    mod lock_for_inner;
    mod pinned_sync_rc_ptr;
    mod sync_rc_ptr_for_inner;
}
