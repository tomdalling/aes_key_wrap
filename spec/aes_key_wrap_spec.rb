require 'spec_helper'

RSpec.describe AESKeyWrap do
  # test data is taken from: http://www.ietf.org/rfc/rfc3394.txt
  TEST_DATA = [
    {
      name: '128bit key, 128bit KEK',
      kek: '000102030405060708090A0B0C0D0E0F',
      unwrapped: '00112233445566778899AABBCCDDEEFF',
      wrapped: '1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5',
    },
    {
      name: '128bit key, 192bit KEK',
      kek: '000102030405060708090A0B0C0D0E0F1011121314151617',
      unwrapped: '00112233445566778899AABBCCDDEEFF',
      wrapped: '96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D',
    },
    {
      name: '128bit key, 256bit KEK',
      kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      unwrapped: '00112233445566778899AABBCCDDEEFF',
      wrapped: '64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7',
    },
    {
      name: '192bit key, 192bit KEK',
      kek: '000102030405060708090A0B0C0D0E0F1011121314151617',
      unwrapped: '00112233445566778899AABBCCDDEEFF0001020304050607',
      wrapped: '031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2',
    },
    {
      name: '192bit key, 256bit KEK',
      kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      unwrapped: '00112233445566778899AABBCCDDEEFF0001020304050607',
      wrapped: 'A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1',
    },
    {
      name: '256bit key, 256bit KEK',
      kek: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      unwrapped: '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F',
      wrapped: '28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21',
    },
  ].each do |data|
    # convert all the hex string into binary
    [:kek, :unwrapped, :wrapped].each do |key|
      data[key] = [data[key].gsub(/\s/, '')].pack('H*')
    end
  end

  CUSTOM_IV = 0xDEADBEEFC0FFEEEE

  describe '#unwrap' do
    it 'unwraps keys' do
      TEST_DATA.each do |data|
        unwrapped = AESKeyWrap.unwrap(data[:wrapped], data[:kek])
        expect(unwrapped).to eq(data[:unwrapped])
      end
    end
  end

  describe '#wrap' do
    it 'wraps keys' do
      TEST_DATA.each do |data|
        wrapped = AESKeyWrap.wrap(data[:unwrapped], data[:kek])
        expect(wrapped).to eq(data[:wrapped])
      end
    end
  end

  it 'handles custom IVs' do
    TEST_DATA.each do |data|
      wrapped = AESKeyWrap.wrap(data[:unwrapped], data[:kek], CUSTOM_IV)
      unwrapped = AESKeyWrap.unwrap(wrapped, data[:kek], CUSTOM_IV)
      expect(unwrapped).to eq(data[:unwrapped])
    end
  end

  it 'detects incorrect IVs' do
    data = TEST_DATA.first
    wrapped = AESKeyWrap.wrap(data[:unwrapped], data[:kek], CUSTOM_IV)
    unwrapped = AESKeyWrap.unwrap(wrapped, data[:kek])
    expect(unwrapped).to be_nil
    expect{
      AESKeyWrap.unwrap!(wrapped, data[:kek])
    }.to raise_error(AESKeyWrap::UnwrapFailedError)
  end
end

