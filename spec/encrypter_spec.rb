require "openssl"
require "tempfile"
require "securerandom"
require "digest/md5"
require_relative '../lib/encrypter.rb'

describe CryptoHelper do
    it "raises ArgumentError without public key" do
        expect do 
            CryptoHelper.new nil 
        end.to raise_error(ArgumentError)
    end

    context "with a keypair" do
        keypair = OpenSSL::PKey::RSA::new 1024
        keyfile = Tempfile.new('keypair')
        keyfile.write(keypair.to_pem)
        keyfile.write(keypair.public_key.to_pem)
        keyfile.close
        crypto = CryptoHelper.new keyfile.path

        it "contains the key" do
            crypto.key.should_not.nil?
        end
        it "fails encrypting empty text" do
            expect do
                crypto.encrypt_text ""
            end.to raise_error(ArgumentError)
        end
        it "fails encrypting nil text" do
            expect do
                crypto.encrypt_text nil 
            end.to raise_error(ArgumentError)
        end
        it "encrypts a text smaller than the key" do
            encrypted = crypto.encrypt_text "some text"
            encrypted.should_not.nil?
        end
        it "fails to encrypt text bigger than the key" do
            expect do
                crypto.encrypt_text "a" * 2048
            end.to raise_error(OpenSSL::PKey::RSAError)
        end
        it "fails decryption if there is only public key" do
            encrypter_only = CryptoHelper.new keypair.public_key
            expect do
            encrypter_only.decrypt_text "some text"
            end.to raise_error(ArgumentError)
        end
        it "encrypts with the public and decrypts with the private" do
            encrypter_only = CryptoHelper.new keypair.public_key
            encrypted_text = encrypter_only.encrypt_text "some text"
            encrypted_text.should_not eq "some text"
            decrypted_text = crypto.decrypt_text encrypted_text
            decrypted_text.should eq "some text"
        end

        context "with a file bigger than the key" do
            bigfile = Tempfile.new('bigfile')
            bigfile.write(SecureRandom.hex) until bigfile.length > 1024 * 16
            bigfile.close
            source = bigfile.path
            source_md5 = Digest::MD5.digest File.read(source)

            it "encrypts and then decrypts the file" do
                source = bigfile.path
                encrypted = Dir::Tmpname::make_tmpname 'encrypted_big_file', nil
                decrypted = Dir::Tmpname::make_tmpname 'decrypted_big_file', nil

                begin
                    crypto.encrypt_file(source, encrypted)
                    encrypted_md5 = Digest::MD5.digest File.read(encrypted)
                    source_md5.should_not eq encrypted_md5

                    crypto.decrypt_file(encrypted, decrypted)
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

describe CryptoOptions do
    it "fails if no mode is passed" do
        expect do
            CryptoOptions.new({"v"=>nil}, [])
        end.to raise_error "mode is mandatory"
    end
    it "fails if an invalid mode is passed" do
        expect do
            CryptoOptions.new({"v"=>nil}, ["invalid"])
        end.to raise_error "invalid mode 'invalid'"
    end
    it "fails if no source is passed" do
        expect do
            CryptoOptions.new({"v"=>nil}, ["e"])
        end.to raise_error "source is mandatory"
    end
    it "uses stdin and stdout if source is -" do
        options = CryptoOptions.new({}, ['e', '-'])
        options.source.should eq STDIN
        options.target.should eq STDOUT
    end
    it "uses file if source is the file" do
        source = Tempfile.new('source')
        options = CryptoOptions.new({}, ['e', source.path])
        options.source.path.should eq source.path
        options.target.should eq STDOUT
    end
    it "uses file if target is a file" do
        target = Tempfile.new('target')
        options = CryptoOptions.new({}, ['e', '-', target.path])
        options.source.should eq STDIN
        options.target.path.should eq target.path
    end
    it "is in encrypt mode if mode is 'e' or 'encrypt'" do
        options = CryptoOptions.new({}, ['e', '-'])
        options.encrypt?.should be true
        options = CryptoOptions.new({}, ['encrypt', '-'])
        options.encrypt?.should be true
    end
    it "is in decrypt mode if mode is 'd' or 'decrypt'" do
        options = CryptoOptions.new({}, ['d', '-'])
        options.encrypt?.should be false
        options = CryptoOptions.new({}, ['decrypt', '-'])
        options.encrypt?.should be false
    end
    it "picks the user ssh key when no key is provided" do
        options = CryptoOptions.new({}, ['d', '-'])
        options.key.should_not.nil?
    end
    it "picks the provided ssh key" do
        target = Tempfile.new('key')
        options = CryptoOptions.new({:key => target.path}, ['d', '-'])
        options.key.should_not.nil?
    end
end
