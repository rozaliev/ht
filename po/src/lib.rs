pub fn decode(ciphertext: Vec<u8>, is_good_padding: impl Fn(&[u8]) -> bool + Copy) -> Vec<u8> {
    let mut plaintext = Vec::new();

    for i in (0..(ciphertext.len() / 16) - 1).rev() {
        println!("block {}", i);
        let im = block(&ciphertext[i * 16..i * 16 + 32], is_good_padding);
        let mut xs = xor_slices(&im, &ciphertext[i * 16..(i + 1) * 16]);
        xs.extend(plaintext);
        plaintext = xs;
        println!("{:?}", plaintext);
    }

    unpad(&mut plaintext);
    plaintext
}

fn block(data: &[u8], is_good_padding: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut inter_state = vec![0; 16];
    let mut test_bytes = data.to_owned();

    let mut history = vec![0; 16];

    let mut byte_i = 15;
    loop {
        println!("byte_i: {}", byte_i);

        let last_good = history[byte_i as usize];

        for cand in history[byte_i as usize]..=255 {
            test_bytes[byte_i as usize] = cand;
            if !is_good_padding(&test_bytes) {
                continue;
            }
            println!("byte_i: {} cand: {}, {:?}", byte_i, cand, test_bytes);
            let cur_pad_i = 16 - byte_i;
            let next_pad_i = 16 - byte_i + 1;
            inter_state[byte_i as usize] = test_bytes[byte_i as usize] ^ cur_pad_i;

            for i in byte_i as usize..16 {
                test_bytes[i] ^= cur_pad_i;
                test_bytes[i] ^= next_pad_i;
            }
            history[byte_i as usize] = cand;
            break;
        }

        if history[byte_i as usize] == last_good {
            println!("not found :(, reseting back");
            byte_i += 1;
        } else if byte_i != 0 {
            byte_i -= 1
        } else {
            break;
        }
    }

    inter_state
}

fn xor_slices(l: &[u8], r: &[u8]) -> Vec<u8> {
    l.iter().zip(r.iter()).map(|(x, y)| x ^ y).collect()
}

fn unpad(d: &mut Vec<u8>) {
    let n = d[d.len() - 1];

    for _ in 0..n {
        d.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes_soft::Aes128;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, Cbc};

    use hex_literal::{hex, hex_impl};

    type Aes128Cbc = Cbc<Aes128, Pkcs7>;

    #[test]
    fn decode_test() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = b"The quick brown fox jumped over the lazy dog";
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
        let ciphertext = cipher.encrypt_vec(plaintext);

        let r = decode(ciphertext, move |s| {
            let d = Aes128Cbc::new_var(&key, &iv).unwrap();
            d.decrypt_vec(s).is_ok()
        });

        assert_eq!(r, &plaintext[16..]);
    }

    #[test]
    fn block_test() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = b"The quick brown fox jumped over the lazy dog";
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
        let mut ciphertext = cipher.encrypt_vec(plaintext);
        let cl = ciphertext.len();
        let r = block(&ciphertext[cl - 32..], move |tc| {
            let d = Aes128Cbc::new_var(&key, &iv).unwrap();

            let r = d.decrypt_vec(tc);
            r.is_ok()
        });

        let pl = plaintext.len();

        let mut test_plain = xor_slices(&r[..], &ciphertext[cl - 32..cl - 16]);
        let tpl = test_plain.len();
        for _ in 0..test_plain[tpl - 1] {
            test_plain.pop();
        }

        assert!(test_plain.len() != 0);
        assert_eq!(test_plain, &plaintext[pl - test_plain.len()..]);
    }
}
