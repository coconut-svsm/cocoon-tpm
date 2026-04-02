use cocoon_tpm_utils_common::io_slices::*;
use core::convert;

#[test]
fn empty_io_slices() {
    let iter = EmptyIoSlices::default();
    {
        // decoupled_borrow returns an independent empty iterator
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow can be called multiple times
        let mut p1 = iter.decoupled_borrow();
        let mut p2 = iter.decoupled_borrow();
        assert_eq!(p1.next_slice(None).unwrap(), None);
        assert_eq!(p2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

#[test]
fn zero_filled_io_slices() {
    const LEN: usize = ZeroFilledIoSlices::CHUNK_SIZE * 2 + 3;
    let expected = [0u8; ZeroFilledIoSlices::CHUNK_SIZE];
    let iter = ZeroFilledIoSlices::new(LEN);
    {
        // decoupled_borrow sees the same data
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[0u8; 3]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow does not advance the original:
        // exhaust peeked1, then verify peeked2 still yields full length
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        // exhaust peeked1
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &[0u8; 3]);
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        // peeked2 still yields the full data
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[0u8; 3]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original
        let mut advanced = ZeroFilledIoSlices::new(LEN);
        advanced.skip(ZeroFilledIoSlices::CHUNK_SIZE).unwrap();
        let mut peeked = advanced.decoupled_borrow();
        // remaining: CHUNK_SIZE + 3
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[0u8; 3]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original is not affected by exhausting the peek
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[0u8; 3]);
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow on empty
        let iter_empty = ZeroFilledIoSlices::new(0);
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[0u8; 3]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

#[test]
fn singleton_io_slice() {
    let buf = [1u8, 2, 3, 4, 5];
    let iter = SingletonIoSlice::new(&buf);
    {
        // decoupled_borrow sees the same data
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled borrows are independent: exhaust one, other still works
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original
        let mut advanced = SingletonIoSlice::new(&buf);
        assert_eq!(advanced.next_slice(Some(2)).unwrap().unwrap(), &buf[..2]);
        let mut peeked = advanced.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf[2..]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected by exhausting the peek
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &buf[2..]);
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow on empty slice
        let iter_empty = SingletonIoSlice::new(&[]);
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

#[test]
fn buffers_slice_io_slices_iter() {
    let buf0 = [1u8, 2];
    let buf1: [u8; 0] = [];
    let buf2 = [3u8, 4, 5];
    let buf3: [u8; 0] = [];
    let slices = [buf0.as_slice(), buf1.as_slice(), buf2.as_slice(), buf3.as_slice()];
    let iter = BuffersSliceIoSlicesIter::new(&slices);
    {
        // decoupled_borrow sees the same data (skipping empties)
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled borrows are independent
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original
        let mut advanced = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(advanced.next_slice(Some(1)).unwrap().unwrap(), &[1]);
        let mut peeked = advanced.decoupled_borrow();
        // remaining head is [2], then [3, 4, 5]
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[2]);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected by exhausting the peek
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[2]);
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow on empty
        let empty_slices: [&[u8]; 0] = [];
        let iter_empty = BuffersSliceIoSlicesIter::new(&empty_slices);
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

#[test]
fn buffers_slice_io_slices_mut_iter() {
    let mut buf0 = [1u8, 2];
    let mut buf1: [u8; 0] = [];
    let mut buf2 = [3u8, 4, 5];
    let mut buf3: [u8; 0] = [];
    let buf0_copy = buf0;
    let buf2_copy = buf2;
    let mut slices = [
        buf0.as_mut_slice(),
        buf1.as_mut_slice(),
        buf2.as_mut_slice(),
        buf3.as_mut_slice(),
    ];
    let iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
    {
        // decoupled_borrow sees the same data (skipping empties)
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf0_copy);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf2_copy);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled borrows are independent
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &buf0_copy);
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &buf2_copy);
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf0_copy);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf2_copy);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original
        let mut buf0b = buf0_copy;
        let mut buf1b: [u8; 0] = [];
        let mut buf2b = buf2_copy;
        let mut buf3b: [u8; 0] = [];
        let mut slices_b = [
            buf0b.as_mut_slice(),
            buf1b.as_mut_slice(),
            buf2b.as_mut_slice(),
            buf3b.as_mut_slice(),
        ];
        let mut advanced = BuffersSliceIoSlicesMutIter::new(&mut slices_b);
        assert_eq!(advanced.next_slice(Some(1)).unwrap().unwrap(), &buf0_copy[..1]);
        let mut peeked = advanced.decoupled_borrow();
        // remaining head is [2], then [3, 4, 5]
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf0_copy[1..]);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf2_copy);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected by exhausting the peek
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &buf0_copy[1..]);
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &buf2_copy);
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow on empty
        let mut empty_slices: [&mut [u8]; 0] = [];
        let iter_empty = BuffersSliceIoSlicesMutIter::new(&mut empty_slices);
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf0_copy);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf2_copy);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

/// Helper to test GenericIoSlicesIter with a given head configuration.
/// Uses const generics so that array copies work without alloc.
fn test_generic_io_slices_iter_peekable_variant(with_head: bool) {
    let buf0 = [1u8, 2];
    let buf1: [u8; 0] = [];
    let buf2 = [3u8, 4, 5];
    let head_buf = [10u8, 11];
    let bufs = [
        Ok::<_, convert::Infallible>(buf0.as_slice()),
        Ok(buf1.as_slice()),
        Ok(buf2.as_slice()),
    ];
    let head = if with_head { Some(head_buf.as_slice()) } else { None };
    let expected_slices: &[&[u8]] = if with_head {
        &[&[10, 11], &[1, 2], &[3, 4, 5]]
    } else {
        &[&[1, 2], &[3, 4, 5]]
    };
    let first = expected_slices[0];
    let iter = GenericIoSlicesIter::new(bufs.clone().into_iter(), head);
    {
        // decoupled_borrow sees the same data (skipping empties)
        let mut peeked = iter.decoupled_borrow();
        for expected in expected_slices {
            assert_eq!(peeked.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled borrows are independent
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        for expected in expected_slices {
            assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        for expected in expected_slices {
            assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original
        let mut advanced = GenericIoSlicesIter::new(bufs.clone().into_iter(), head);
        assert_eq!(advanced.next_slice(Some(1)).unwrap().unwrap(), &first[..1]);
        let mut peeked = advanced.decoupled_borrow();
        // remaining head is first[1..], then the rest
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &first[1..]);
        for expected in &expected_slices[1..] {
            assert_eq!(peeked.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected by exhausting the peek
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &first[1..]);
        for expected in &expected_slices[1..] {
            assert_eq!(advanced.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        for expected in expected_slices {
            assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

#[test]
fn generic_io_slices_iter() {
    // without head
    test_generic_io_slices_iter_peekable_variant(false);

    // with head
    test_generic_io_slices_iter_peekable_variant(true);

    {
        // decoupled_borrow on empty
        let iter_empty = GenericIoSlicesIter::new([Ok::<&[u8], convert::Infallible>(&[]); 0].into_iter(), None);
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
}

#[test]
fn singleton_io_slice_mut() {
    let mut buf = [1u8, 2, 3, 4, 5];
    let buf_copy = buf;
    let iter = SingletonIoSliceMut::new(&mut buf);
    {
        // decoupled_borrow sees the same data
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf_copy);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled borrows are independent: exhaust one, other still works
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &buf_copy);
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf_copy);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original
        let mut buf2 = buf_copy;
        let mut advanced = SingletonIoSliceMut::new(&mut buf2);
        assert_eq!(advanced.next_slice(Some(2)).unwrap().unwrap(), &buf_copy[..2]);
        let mut peeked = advanced.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf_copy[2..]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected by exhausting the peek
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &buf_copy[2..]);
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow on empty slice
        let mut empty = [0u8; 0];
        let iter_empty = SingletonIoSliceMut::new(&mut empty);
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf_copy);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

#[test]
fn covariant_io_slices_iter_ref() {
    let buf = [1u8, 2, 3, 4, 5];
    let mut inner = SingletonIoSlice::new(&buf);
    let iter = inner.as_ref();
    {
        // decoupled_borrow sees the same data
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled borrows are independent
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original
        let mut inner2 = SingletonIoSlice::new(&buf);
        let mut covariant = inner2.as_ref();
        assert_eq!(covariant.next_slice(Some(2)).unwrap().unwrap(), &buf[..2]);
        let mut peeked = covariant.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &buf[2..]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected by exhausting the peek
        assert_eq!(covariant.next_slice(None).unwrap().unwrap(), &buf[2..]);
        assert_eq!(covariant.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow on empty
        let mut inner_empty = SingletonIoSlice::new(&[]);
        let iter_empty = inner_empty.as_ref();
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

#[test]
fn io_slices_iter_map_err() {
    #[derive(Debug)]
    struct MappedError;
    let map_fn = |_: convert::Infallible| -> MappedError { unreachable!() };

    let buf0 = [1u8, 2];
    let buf1: [u8; 0] = [];
    let buf2 = [3u8, 4, 5];
    let slices = [buf0.as_slice(), buf1.as_slice(), buf2.as_slice()];
    let iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
    {
        // decoupled_borrow sees the same data (skipping empties)
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled borrows are independent
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original
        let mut advanced = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        assert_eq!(advanced.next_slice(Some(1)).unwrap().unwrap(), &[1]);
        let mut peeked = advanced.decoupled_borrow();
        // remaining head is [2], then [3, 4, 5]
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[2]);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected by exhausting the peek
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[2]);
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow on empty
        let empty_slices: [&[u8]; 0] = [];
        let iter_empty = BuffersSliceIoSlicesIter::new(&empty_slices).map_err(map_fn);
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

#[test]
fn io_slices_iter_take_exact() {
    let buf0 = [1u8, 2];
    let buf1 = [3u8, 4, 5, 6, 7, 8];
    let slices = [buf0.as_slice(), buf1.as_slice()];
    // take_exact(5): yields [1, 2] then [3, 4, 5]
    let iter = BuffersSliceIoSlicesIter::new(&slices).take_exact(5);
    {
        // decoupled_borrow sees the same data
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled borrows are independent
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original
        let mut advanced = BuffersSliceIoSlicesIter::new(&slices).take_exact(5);
        assert_eq!(advanced.next_slice(Some(1)).unwrap().unwrap(), &[1]);
        let mut peeked = advanced.decoupled_borrow();
        // remaining: [2] then [3, 4, 5]
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[2]);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected by exhausting the peek
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[2]);
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow on zero-length take
        let iter_empty = BuffersSliceIoSlicesIter::new(&slices).take_exact(0);
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}

#[test]
fn io_slices_iter_chain() {
    let buf0 = [1u8, 2];
    let slices0 = [buf0.as_slice()];
    let buf1 = [3u8, 4, 5];
    let slices1 = [buf1.as_slice()];
    let iter = IoSlicesIterCommon::chain(
        BuffersSliceIoSlicesIter::new(&slices0),
        BuffersSliceIoSlicesIter::new(&slices1),
    );
    {
        // decoupled_borrow sees the same data
        let mut peeked = iter.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled borrows are independent
        let mut peeked1 = iter.decoupled_borrow();
        let mut peeked2 = iter.decoupled_borrow();
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked1.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked1.next_slice(None).unwrap(), None);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing original past the first half
        let mut advanced = IoSlicesIterCommon::chain(
            BuffersSliceIoSlicesIter::new(&slices0),
            BuffersSliceIoSlicesIter::new(&slices1),
        );
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[1, 2]);
        let mut peeked = advanced.decoupled_borrow();
        // remaining: only the second half
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected by exhausting the peek
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow after advancing into the middle of a slice
        let mut advanced = IoSlicesIterCommon::chain(
            BuffersSliceIoSlicesIter::new(&slices0),
            BuffersSliceIoSlicesIter::new(&slices1),
        );
        assert_eq!(advanced.next_slice(Some(1)).unwrap().unwrap(), &[1]);
        let mut peeked = advanced.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[2]);
        assert_eq!(peeked.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked.next_slice(None).unwrap(), None);
        // original unaffected
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[2]);
        assert_eq!(advanced.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(advanced.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow on empty chain
        let empty0: [&[u8]; 0] = [];
        let empty1: [&[u8]; 0] = [];
        let iter_empty = IoSlicesIterCommon::chain(
            BuffersSliceIoSlicesIter::new(&empty0),
            BuffersSliceIoSlicesIter::new(&empty1),
        );
        let mut peeked = iter_empty.decoupled_borrow();
        assert_eq!(peeked.next_slice(None).unwrap(), None);
    }
    {
        // decoupled_borrow of decoupled_borrow
        let peeked = iter.decoupled_borrow();
        let mut peeked2 = peeked.decoupled_borrow();
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[1, 2]);
        assert_eq!(peeked2.next_slice(None).unwrap().unwrap(), &[3, 4, 5]);
        assert_eq!(peeked2.next_slice(None).unwrap(), None);
    }
}
