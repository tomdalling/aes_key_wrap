require_relative '../test_init'

TestBench.context AESKeyWrap do

  class Oracle
    include TestBench::Fixture

    attr_accessor :kek, :plaintext_key, :wrapped_key

    def initialize(kek:, plaintext_key:, wrapped_key:)
      hex2bin = ->(hex_str) { [hex_str.gsub(/\s+/, '')].pack("H*") }

      @kek = hex2bin.(kek)
      @plaintext_key = hex2bin.(plaintext_key)
      @wrapped_key = hex2bin.(wrapped_key)
    end

    def call
      context "given a #{plaintext_key.length * 8}-bit key and #{kek.length * 8}-bit KEK" do

        context "absent a custom IV argument" do
          test "wraps the plaintext key" do
            assert(AESKeyWrap.wrap(plaintext_key, kek) == wrapped_key)
          end

          test "wraps with the default IV from RFC 3394" do
            assert(
              AESKeyWrap.wrap(plaintext_key, kek) \
              ==
              AESKeyWrap.wrap(plaintext_key, kek, 0xA6A6A6A6A6A6A6A6)
            )
          end

          test "unwraps the wrapped key" do
            assert(AESKeyWrap.unwrap(wrapped_key, kek) == plaintext_key)
          end

          test "unwraps to nil on failure (e.g. IV is not the default from RFC 3394)" do
            wrapped_key_with_custom_iv = AESKeyWrap.wrap(plaintext_key, kek, 0xDEADBEEFC0FFEEEE)
            assert(AESKeyWrap.unwrap(wrapped_key_with_custom_iv, kek).nil?)
          end
        end

        context "given a custom IV argument" do
          wrapped_key_with_custom_iv = AESKeyWrap.wrap(plaintext_key, kek, 0xDEADBEEFC0FFEEEE)

          test "still wraps plaintext keys" do
            refute(wrapped_key_with_custom_iv.empty?)
          end

          test "still unwraps wrapped keys" do
            assert(
              AESKeyWrap.unwrap(wrapped_key_with_custom_iv, kek, 0xDEADBEEFC0FFEEEE) \
              == plaintext_key
            )
          end

          test "still unwraps to nil on failure (e.g. if the IV is wrong)" do
            assert(AESKeyWrap.unwrap(wrapped_key, kek, 12345).nil?)
          end
        end

      end
    end
  end

  # test data is taken from: http://www.ietf.org/rfc/rfc3394.txt
  [
    {
      kek: '000102030405060708090A0B0C0D0E0F',
      plaintext_key: '00112233445566778899AABBCCDDEEFF',
      wrapped_key: '1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5',
    },
    {
      kek: '000102030405060708090A0B0C0D0E0F1011121314151617',
      plaintext_key: '00112233445566778899AABBCCDDEEFF',
      wrapped_key: '96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D',
    },
    {
      kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      plaintext_key: '00112233445566778899AABBCCDDEEFF',
      wrapped_key: '64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7',
    },
    {
      kek: '000102030405060708090A0B0C0D0E0F1011121314151617',
      plaintext_key: '00112233445566778899AABBCCDDEEFF0001020304050607',
      wrapped_key: '031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2',
    },
    {
      kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      plaintext_key: '00112233445566778899AABBCCDDEEFF0001020304050607',
      wrapped_key: 'A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1',
    },
    {
      kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      plaintext_key: '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F',
      wrapped_key: '28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21',
    },
  ].each { |truth| fixture(Oracle, **truth) }

  context 'the exception-raising version of unwrap' do
    dummy_arg = "X"*16
    wrapped = AESKeyWrap.wrap(dummy_arg, dummy_arg, 1234)

    test 'has the same return value on success' do
      unwrapped = AESKeyWrap.unwrap!(wrapped, dummy_arg, 1234)
      assert(unwrapped == dummy_arg)
    end

    test 'raises an exception on failure, instead of returning nil' do
      assert_raises(AESKeyWrap::UnwrapFailedError) do
        AESKeyWrap.unwrap!(wrapped, dummy_arg, 5678)
      end
    end
  end

  context "IVs" do
    wrap_using_iv = ->(iv) { AESKeyWrap.wrap("!"*16, "?"*16, iv) }

    test "can be 64-bit unsigned integers" do
      refute_raises { wrap_using_iv.(0xDEADBEEFC0FFEEEE) }
    end

    test "can be 8-byte strings" do
      refute_raises { wrap_using_iv.("\xDE\xAD\xBE\xEF\xC0\xFF\xEE\xEE") }
    end

    test "are equivalent, regardless of type" do
      i64 = wrap_using_iv.(0xDEADBEEFC0FFEEEE)
      str = wrap_using_iv.("\xDE\xAD\xBE\xEF\xC0\xFF\xEE\xEE")
      assert(i64 == str)
    end

    test "can not be larger integers" do
      assert_raises(ArgumentError, 'IV is too large to fit in a 64-bit unsigned integer') do
        wrap_using_iv.(0x10000000000000000)
      end
    end

    test "can not be negative integers" do
      assert_raises(ArgumentError, "IV is not an unsigned integer (it's negative)") do
        wrap_using_iv.(-1)
      end
    end

    test "can not be strings of any other length" do
      assert_raises(ArgumentError, "IV is not 8 bytes long") do
        wrap_using_iv.('hello')
      end
    end

    test "can not be any other type of value" do
      assert_raises(ArgumentError, "IV is not valid: :elmo") do
        wrap_using_iv.(:elmo)
      end
    end
  end
end
