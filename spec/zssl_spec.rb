require "openssl"
require "tempfile"
require "securerandom"
require "digest/md5"
require 'zssl'

describe Zoocial::Cipher do
    it "raises ArgumentError without public key" do
        expect do 
            Zoocial::Cipher.new nil 
        end.to raise_error(ArgumentError)
    end

    context "with a keypair" do
        key_size = 4096
        keypair = OpenSSL::PKey::RSA::new key_size
        keyfile = Tempfile.new('keypair')
        keyfile.write(keypair.to_pem)
        keyfile.write(keypair.public_key.to_pem)
        keyfile.close
        crypto = Zoocial::Cipher.new keyfile.path

        it "contains the key" do
            crypto.key.should_not.nil?
        end

        context "with a source file" do
            bigfile = Tempfile.new('bigfile')
            bigfile.write(SecureRandom.hex) until bigfile.length > key_size * 16
            bigfile.close
            source = bigfile.path
            source_md5 = Digest::MD5.digest File.read(source)

            it "encrypts and then decrypts the file" do
                source = bigfile.path
                encrypted = Dir::Tmpname::make_tmpname 'encrypted_big_file', nil
                decrypted = Dir::Tmpname::make_tmpname 'decrypted_big_file', nil

                begin
                    crypto.encrypt(source, encrypted)
                    encrypted_md5 = Digest::MD5.digest File.read(encrypted)
                    source_md5.should_not eq encrypted_md5

                    crypto.decrypt(encrypted, decrypted)
                    decrypted_md5 = Digest::MD5.digest File.read(decrypted)
                    decrypted_md5.should eq source_md5
                ensure
                    File.delete encrypted
                    File.delete decrypted
                end
            end
        end
    end
end

describe Zoocial::CipherOptions do
    it "fails if no mode is passed" do
        expect do
            Zoocial::CipherOptions.new({"v"=>nil}, [])
        end.to raise_error "mode is mandatory"
    end
    it "fails if an invalid mode is passed" do
        expect do
            Zoocial::CipherOptions.new({"v"=>nil}, ["invalid"])
        end.to raise_error "invalid mode 'invalid'"
    end
    it "fails if no source is passed" do
        expect do
            Zoocial::CipherOptions.new({"v"=>nil}, ["e"])
        end.to raise_error "source is mandatory"
    end
    it "uses stdin and stdout if source is -" do
        options = Zoocial::CipherOptions.new({}, ['e', '-'])
        options.source.should eq STDIN
        options.target.should eq STDOUT
    end
    it "uses file if source is the file" do
        source = Tempfile.new('source')
        options = Zoocial::CipherOptions.new({}, ['e', source.path])
        options.source.path.should eq source.path
        options.target.should eq STDOUT
    end
    it "uses file if target is a file" do
        target = Tempfile.new('target')
        options = Zoocial::CipherOptions.new({}, ['e', '-', target.path])
        options.source.should eq STDIN
        options.target.path.should eq target.path
    end
    it "is in encrypt mode if mode is 'e' or 'encrypt'" do
        options = Zoocial::CipherOptions.new({}, ['e', '-'])
        options.encrypt?.should be true
        options = Zoocial::CipherOptions.new({}, ['encrypt', '-'])
        options.encrypt?.should be true
    end
    it "is in decrypt mode if mode is 'd' or 'decrypt'" do
        options = Zoocial::CipherOptions.new({}, ['d', '-'])
        options.encrypt?.should be false
        options = Zoocial::CipherOptions.new({}, ['decrypt', '-'])
        options.encrypt?.should be false
    end
    it "picks the user ssh key when no key is provided" do
        options = Zoocial::CipherOptions.new({}, ['d', '-'])
        options.key.should_not.nil?
    end
    it "picks the provided ssh key" do
        target = Tempfile.new('key')
        options = Zoocial::CipherOptions.new({:key => target.path}, ['d', '-'])
        options.key.should_not.nil?
    end
end
