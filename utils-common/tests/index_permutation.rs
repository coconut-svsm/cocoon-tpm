mod index_permutation {
    use cocoon_tpm_utils_common::index_permutation::*;
    const IDENTITY_7: [usize; 7] = [0usize, 1, 2, 3, 4, 5, 6];
    const DATA_7: [u8; 7] = [0u8, 1, 2, 3, 4, 5, 6];
    mod apply_index_perm {
        use super::*;

        #[test]
        fn identity() {
            let mut d = DATA_7;
            let mut p = IDENTITY_7;

            apply_index_perm(&mut p, &mut d);
            assert_eq!(d, DATA_7);
            assert_eq!(p, IDENTITY_7);
        }

        #[test]
        fn shift() {
            let mut d = DATA_7;
            let mut p = [1usize, 2, 3, 4, 5, 6, 0];

            apply_index_perm(&mut p, &mut d);
            assert_eq!(d, [1u8, 2, 3, 4, 5, 6, 0], "data array differs");
            assert_eq!(p, IDENTITY_7, "index array differs");
        }

        #[test]
        fn swap() {
            let mut d = DATA_7;
            let mut p = [0usize, 1, 3, 2, 4, 6, 5];

            apply_index_perm(&mut p, &mut d);
            assert_eq!(d, [0u8, 1, 3, 2, 4, 6, 5], "data array differs");
            assert_eq!(p, IDENTITY_7, "index array differs");
        }

        #[test]
        fn swap_2() {
            let mut d = DATA_7;
            let mut p = [1usize, 0, 2, 3, 4, 6, 5];

            apply_index_perm(&mut p, &mut d);
            assert_eq!(d, [1u8, 0, 2, 3, 4, 6, 5], "data array differs");
            assert_eq!(p, IDENTITY_7, "index array differs");
        }

        #[test]
        fn reverse() {
            let mut d = DATA_7;
            let mut p = [6usize, 5, 4, 3, 2, 1, 0];

            apply_index_perm(&mut p, &mut d);
            assert_eq!(d, [6u8, 5, 4, 3, 2, 1, 0], "data array differs");
            assert_eq!(p, IDENTITY_7, "index array differs");
        }

        #[test]
        fn empty() {
            let mut d: [u8; 0] = [];
            let mut p: [usize; 0] = [];
            apply_index_perm(&mut p, &mut d);
        }

        #[test]
        fn single() {
            let mut d = [42u8];
            let mut p = [0usize];
            apply_index_perm(&mut p, &mut d);
            assert_eq!(d, [42u8], "data array differs");
            assert_eq!(p, [0usize], "index array differs");
        }

        #[test]
        fn two_disjoint_cycles() {
            // 3-cycle (0->1->2->0) and 2-cycle (3<->4), plus fixed points 5,6.
            let mut d = DATA_7;
            let mut p = [1usize, 2, 0, 4, 3, 5, 6];

            apply_index_perm(&mut p, &mut d);
            assert_eq!(d, [1u8, 2, 0, 4, 3, 5, 6], "data array differs");
            assert_eq!(p, IDENTITY_7, "index array differs");
        }

        #[test]
        fn large_and_small_cycle() {
            // 4-cycle (0->1->2->3->0) and 2-cycle (4<->5).
            let mut d = DATA_7;
            let mut p = [1usize, 2, 3, 0, 5, 4, 6];

            apply_index_perm(&mut p, &mut d);
            assert_eq!(d, [1u8, 2, 3, 0, 5, 4, 6], "data array differs");
            assert_eq!(p, IDENTITY_7, "index array differs");
        }
    }

    mod apply_and_invert_index_perm {
        use super::*;
        #[test]
        fn apply_and_invert_identity() {
            let mut d = DATA_7;
            let mut p = IDENTITY_7;
            apply_and_invert_index_perm(&mut p, &mut d);
            assert_eq!(d, DATA_7, "data array differs");
            assert_eq!(p, IDENTITY_7, "inverse permutation differs");
        }

        #[test]
        fn apply_and_invert_shift() {
            let mut d = DATA_7;
            let mut p = [1usize, 2, 3, 4, 5, 6, 0];

            apply_and_invert_index_perm(&mut p, &mut d);
            assert_eq!(d, [1u8, 2, 3, 4, 5, 6, 0], "data array differs");
            // Inverse of [1,2,3,4,5,6,0] is [6,0,1,2,3,4,5].
            assert_eq!(p, [6usize, 0, 1, 2, 3, 4, 5], "inverse permutation differs");
        }

        #[test]
        fn apply_and_invert_swap() {
            let mut d = DATA_7;
            let p_start = [1usize, 0, 2, 4, 3, 5, 6];
            let mut p = p_start;

            apply_and_invert_index_perm(&mut p, &mut d);
            assert_eq!(d, [1u8, 0, 2, 4, 3, 5, 6], "data array differs");
            // Swaps are self-inverse.
            assert_eq!(p, [1usize, 0, 2, 4, 3, 5, 6], "inverse permutation differs");
        }

        #[test]
        fn roundtrip() {
            // Apply a permutation, then apply its inverse to restore the original.
            // Two 3-cycles: (0->1->2->0), (3->4->5->3), plus fixed point 6.
            let mut d = DATA_7;
            let mut p = [1usize, 2, 0, 4, 5, 3, 6];

            apply_and_invert_index_perm(&mut p, &mut d);
            assert_eq!(d, [1u8, 2, 0, 4, 5, 3, 6], "data array differs");
            // Verify the inverse permutation.
            assert_eq!(p, [2usize, 0, 1, 5, 3, 4, 6], "inverse permutation differs");
            // Applying the inverse should restore the original data.
            apply_index_perm(&mut p, &mut d);
            assert_eq!(d, DATA_7, "roundtrip failed to restore data");
        }
    }
}
