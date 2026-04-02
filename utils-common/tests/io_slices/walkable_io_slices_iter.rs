use cocoon_tpm_utils_common::io_slices::*;
use core::convert;

#[test]
fn empty_io_slices() {
    let io_slice = EmptyIoSlices::default();
    {
        // total len
        assert_eq!(io_slice.total_len().unwrap(), 0);
    }

    {
        // for each
        io_slice
            .for_each(&mut |_| {
                assert!(false, "This should never be called");
                true
            })
            .unwrap();
    }

    {
        // all_lengths_multiple_of
        assert!(!io_slice.all_lengths_multiple_of(0).unwrap());
        assert!(io_slice.all_lengths_multiple_of(5).unwrap());
        assert!(io_slice.all_lengths_multiple_of(1).unwrap());
        assert!(io_slice.all_lengths_multiple_of(4223).unwrap());
    }
}

#[test]
fn io_slices_iter_chain() {
    let buffer1 = [0u8, 1, 2, 3, 4];
    let slices1 = [buffer1.as_slice()];
    let buffer2 = [5u8, 6, 7];
    let slices2 = [buffer2.as_slice()];
    let buffer3 = [5u8, 6, 7, 8, 9];
    let slices3 = [buffer3.as_slice()];

    {
        // total len
        let chain = IoSlicesIterCommon::chain(
            BuffersSliceIoSlicesIter::new(&slices1),
            BuffersSliceIoSlicesIter::new(&slices2),
        );

        assert_eq!(chain.total_len().unwrap(), buffer1.len() + buffer2.len());
    }

    {
        // for each
        let chain = IoSlicesIterCommon::chain(
            BuffersSliceIoSlicesIter::new(&slices1),
            BuffersSliceIoSlicesIter::new(&slices2),
        );
        let all_slices = [buffer1.as_slice(), buffer2.as_slice()];
        let mut i = all_slices.iter();

        chain
            .for_each(&mut |v| {
                assert_eq!(v, *i.next().unwrap());
                true
            })
            .unwrap();
        assert!(i.next().is_none());
    }

    {
        // all_lengths_multiple_of
        {
            let chain_zero = IoSlicesIterCommon::chain(
                BuffersSliceIoSlicesIter::new(&slices1),
                BuffersSliceIoSlicesIter::new(&slices2),
            );
            assert!(!chain_zero.all_lengths_multiple_of(0).unwrap());
        }
        {
            let chain_same_length = IoSlicesIterCommon::chain(
                BuffersSliceIoSlicesIter::new(&slices1),
                BuffersSliceIoSlicesIter::new(&slices3),
            );
            assert!(chain_same_length.all_lengths_multiple_of(5).unwrap());
        }
        {
            let chain_different_length = IoSlicesIterCommon::chain(
                BuffersSliceIoSlicesIter::new(&slices1),
                BuffersSliceIoSlicesIter::new(&slices2),
            );
            assert!(!chain_different_length.all_lengths_multiple_of(5).unwrap());
        }
    }
}

#[test]
fn zero_filled_io_slices() {
    const LEN: usize = ZeroFilledIoSlices::CHUNK_SIZE * 2 + 3;
    let slice = ZeroFilledIoSlices::new(LEN);
    {
        // total len
        assert_eq!(slice.total_len().unwrap(), LEN);
    }

    {
        // for each
        let expected1 = [0u8; ZeroFilledIoSlices::CHUNK_SIZE];
        let expected2 = [0u8; 3];
        let expected = [expected1.as_slice(), expected1.as_slice(), expected2.as_slice()];
        let mut i = expected.iter();
        slice
            .for_each(&mut |v| {
                assert_eq!(v, *i.next().unwrap());
                true
            })
            .unwrap();
        assert!(i.next().is_none());
    }

    {
        // all_lengths_multiple_of
        assert!(!slice.all_lengths_multiple_of(0).unwrap());
        assert!(slice.all_lengths_multiple_of(1).unwrap());
        assert!(!slice.all_lengths_multiple_of(4).unwrap());
        assert!(slice.all_lengths_multiple_of(5).unwrap());
        assert!(!slice.all_lengths_multiple_of(17).unwrap());
    }
}

#[test]
fn io_slices_take_exact() {
    let buffer1 = [0u8, 1];
    let buffer2 = [2u8, 3, 4, 5, 6, 7, 8, 9];
    let slices = [buffer1.as_slice(), buffer2.as_slice()];

    {
        // total len
        let take_exact = BuffersSliceIoSlicesIter::new(&slices).take_exact(5);

        assert_eq!(take_exact.total_len().unwrap(), 5);
    }

    {
        let mut take_exact = BuffersSliceIoSlicesIter::new(&slices).take_exact(4);
        assert_eq!(take_exact.next_slice(None).unwrap().unwrap(), buffer1);
        assert_eq!(take_exact.next_slice(None).unwrap().unwrap(), &buffer2[0..2]);
        assert!(take_exact.next_slice(None).unwrap().is_none());
    }

    {
        // for each
        let take_exact = BuffersSliceIoSlicesIter::new(&slices).take_exact(4);
        let all_slices = [buffer1.as_slice(), &buffer2[0..2]];
        let mut i = all_slices.iter();

        take_exact
            .for_each(&mut |v| {
                assert_eq!(v, *i.next().unwrap());
                true
            })
            .unwrap();
        assert!(i.next().is_none());
    }

    {
        // all_lengths_multiple_of
        {
            let take_exact = BuffersSliceIoSlicesIter::new(&slices).take_exact(4);
            assert!(!take_exact.all_lengths_multiple_of(0).unwrap());
        }
        {
            let take_exact = BuffersSliceIoSlicesIter::new(&slices).take_exact(4);
            // Lengths are 2 and 2
            assert!(take_exact.all_lengths_multiple_of(2).unwrap());
            assert!(!take_exact.all_lengths_multiple_of(4).unwrap());
            assert!(!take_exact.all_lengths_multiple_of(5).unwrap());
        }
        {
            let take_exact = BuffersSliceIoSlicesIter::new(&slices).take_exact(3);
            // Lengths are 2 and 1
            assert!(take_exact.all_lengths_multiple_of(1).unwrap());
            assert!(!take_exact.all_lengths_multiple_of(3).unwrap());
            assert!(!take_exact.all_lengths_multiple_of(4).unwrap());
            assert!(!take_exact.all_lengths_multiple_of(5).unwrap());
        }
        {
            let take_exact = BuffersSliceIoSlicesIter::new(&slices).take_exact(5);
            // Lengths are 2 and 3.
            assert!(take_exact.all_lengths_multiple_of(1).unwrap());
            assert!(!take_exact.all_lengths_multiple_of(2).unwrap());
            assert!(!take_exact.all_lengths_multiple_of(3).unwrap());
            assert!(!take_exact.all_lengths_multiple_of(4).unwrap());
            assert!(!take_exact.all_lengths_multiple_of(5).unwrap());
        }
    }
}

#[test]
fn singleton_io_slice_iter() {
    let slice = [0u8, 1, 2, 3, 4, 5];
    {
        // total len
        let io_slice = SingletonIoSlice::new(&slice);
        assert_eq!(io_slice.total_len().unwrap(), 6);
    }

    {
        // for each
        let io_slice = SingletonIoSlice::new(&slice);
        let slices = [slice.as_slice()];
        let mut i = slices.iter();
        io_slice
            .for_each(&mut |v| {
                assert_eq!(v, *i.next().unwrap());
                true
            })
            .unwrap();
        assert!(i.next().is_none());
    }

    {
        // all_lengths_multiple_of
        let io_slice = SingletonIoSlice::new(&slice);
        assert!(!io_slice.all_lengths_multiple_of(0).unwrap());
        assert!(io_slice.all_lengths_multiple_of(6).unwrap());
        assert!(io_slice.all_lengths_multiple_of(3).unwrap());
        assert!(!io_slice.all_lengths_multiple_of(5).unwrap());
    }
}

#[test]
fn generic_io_slices_iter() {
    let prefix = [0u8, 1];
    let buffer1 = [2u8, 3, 4, 5];
    let buffer2 = [6u8, 7, 8, 9];
    {
        // without "head"
        let iter = GenericIoSlicesIter::new(
            [Ok::<_, convert::Infallible>(buffer1.as_slice()), Ok(buffer2.as_slice())].into_iter(),
            None,
        );

        // total_len
        assert_eq!(iter.total_len().unwrap(), buffer1.len() + buffer2.len());

        // all_lengths_multiple_of
        assert!(!iter.all_lengths_multiple_of(0).unwrap());
        assert!(iter.all_lengths_multiple_of(4).unwrap());
        assert!(!iter.all_lengths_multiple_of(5).unwrap());

        // for_each
        let slices = [buffer1.as_slice(), buffer2.as_slice()];
        let mut i = slices.iter();
        iter.for_each(&mut |v| {
            assert_eq!(v, *i.next().unwrap());
            true
        })
        .unwrap();
        assert!(i.next().is_none());
    }

    {
        // with "head"
        let iter = GenericIoSlicesIter::new(
            [Ok::<_, convert::Infallible>(buffer1.as_slice()), Ok(buffer2.as_slice())].into_iter(),
            Some(prefix.as_slice()),
        );

        // total_len
        assert_eq!(iter.total_len().unwrap(), buffer1.len() + buffer2.len() + prefix.len());

        // all_lengths_multiple_of
        assert!(!iter.all_lengths_multiple_of(0).unwrap());
        assert!(iter.all_lengths_multiple_of(2).unwrap());
        assert!(!iter.all_lengths_multiple_of(4).unwrap());
        assert!(!iter.all_lengths_multiple_of(5).unwrap());

        // for_each
        let slices = [prefix.as_slice(), buffer1.as_slice(), buffer2.as_slice()];
        let mut i = slices.iter();
        iter.for_each(&mut |v| {
            assert_eq!(v, *i.next().unwrap());
            true
        })
        .unwrap();
        assert!(i.next().is_none());
    }
}

#[test]
fn covariant_io_slices_iter() {
    let buffer1 = [0u8, 1];
    let buffer2 = [2u8, 3, 4, 5, 6, 7, 8, 9];
    let slices = [buffer1.as_slice(), buffer2.as_slice()];

    let mut iter1 = BuffersSliceIoSlicesIter::new(&slices);
    let iter = iter1.as_ref();

    // total len
    assert_eq!(iter.total_len().unwrap(), buffer1.len() + buffer2.len());

    // all_lengths_multiple_of
    assert!(!iter.all_lengths_multiple_of(0).unwrap());
    assert!(iter.all_lengths_multiple_of(2).unwrap());
    assert!(!iter.all_lengths_multiple_of(4).unwrap());

    // for_each
    let mut i = slices.iter();
    iter.for_each(&mut |v| {
        assert_eq!(v, *i.next().unwrap());
        true
    })
    .unwrap();
    assert!(i.next().is_none());
}

#[test]
fn buffers_slice_io_slices_mut_iter() {
    let mut buf0 = [0u8, 1, 2];
    let mut buf1 = [3u8, 4, 5, 6, 7, 8];
    let buf0_copy = buf0;
    let buf1_copy = buf1;
    let mut slices = [buf0.as_mut_slice(), buf1.as_mut_slice()];
    let iter = BuffersSliceIoSlicesMutIter::new(&mut slices);

    // total_len
    assert_eq!(iter.total_len().unwrap(), buf0_copy.len() + buf1_copy.len());

    // all_lengths_multiple_of
    assert!(!iter.all_lengths_multiple_of(0).unwrap());
    assert!(iter.all_lengths_multiple_of(3).unwrap());
    assert!(iter.all_lengths_multiple_of(1).unwrap());
    assert!(!iter.all_lengths_multiple_of(4).unwrap());
    assert!(!iter.all_lengths_multiple_of(5).unwrap());

    // for_each
    let expected = [buf0_copy.as_slice(), buf1_copy.as_slice()];
    let mut i = expected.iter();
    WalkableIoSlicesIter::for_each(&iter, &mut |v| {
        assert_eq!(v, *i.next().unwrap());
        true
    })
    .unwrap();
    assert!(i.next().is_none());
}

#[test]
fn singleton_io_slice_mut_iter() {
    let mut buf = [0u8, 1, 2, 3, 4, 5];
    let buf_copy = buf;
    let iter = SingletonIoSliceMut::new(&mut buf);

    // total_len
    assert_eq!(iter.total_len().unwrap(), 6);

    // all_lengths_multiple_of
    assert!(!iter.all_lengths_multiple_of(0).unwrap());
    assert!(iter.all_lengths_multiple_of(6).unwrap());
    assert!(iter.all_lengths_multiple_of(3).unwrap());
    assert!(!iter.all_lengths_multiple_of(5).unwrap());

    // for_each
    let expected = [buf_copy.as_slice()];
    let mut i = expected.iter();
    iter.for_each(&mut |v| {
        assert_eq!(v, *i.next().unwrap());
        true
    })
    .unwrap();
    assert!(i.next().is_none());
}

#[test]
fn io_slices_iter_map_err() {
    #[derive(Debug)]
    struct MappedError;
    let map_fn = |_: convert::Infallible| -> MappedError { unreachable!() };

    let buf0 = [0u8, 1, 2];
    let buf1 = [3u8, 4, 5, 6, 7, 8];
    let slices = [buf0.as_slice(), buf1.as_slice()];
    let iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);

    // total_len
    assert_eq!(iter.total_len().unwrap(), buf0.len() + buf1.len());

    // all_lengths_multiple_of
    assert!(!iter.all_lengths_multiple_of(0).unwrap());
    assert!(iter.all_lengths_multiple_of(3).unwrap());
    assert!(iter.all_lengths_multiple_of(1).unwrap());
    assert!(!iter.all_lengths_multiple_of(4).unwrap());
    assert!(!iter.all_lengths_multiple_of(5).unwrap());

    // for_each
    let expected = [buf0.as_slice(), buf1.as_slice()];
    let mut i = expected.iter();
    iter.for_each(&mut |v| {
        assert_eq!(v, *i.next().unwrap());
        true
    })
    .unwrap();
    assert!(i.next().is_none());
}
