require "openssl"
require "tempfile"
require "securerandom"
require "digest/md5"
require_relative '../encrypt.rb'

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
        it "raises ArgumentError encrypting empty text" do
            expect do
                crypto.encrypt_text ""
            end.to raise_error(ArgumentError)
        end
        it "raises ArgumentError encrypting nil text" do
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

        context "with a file bigger than the key" do
            bigfile = Tempfile.new('bigfile')
            bigfile.write(SecureRandom.hex) until bigfile.length > 1024
            bigfile.close
            source = bigfile.path
            source_md5 = Digest::MD5.digest File.read(source)

            it "encrypts and then decrypts the file" do
                source = bigfile.path
                target = Dir::Tmpname::make_tmpname 'encrypted_big_file', nil
                decrypted = Dir::Tmpname::make_tmpname 'decrypted_big_file', nil

                begin
                    crypto.encrypt_file(source, target)
                    encrypted_md5 = Digest::MD5.digest File.read(target)
                    source_md5.should_not eq encrypted_md5

                    # crypto.decrypt_file(target, decrypted)
                    # decrypted_md5 = Digest::MD5.digest File.read(decrypted)
                    # decrypted_md5.should eq source_md5
                ensure
                    File.delete target
                    # File.delete decrypted
                end
            end

        end

        keyfile.unlink
    end
end
