require 'spec_helper'
require 'zssl'
require "tempfile"
require "digest/md5"

module Zoocial

  describe Cipher do

    it "errs without public key" do
      expect do
        Cipher.new nil
      end.to raise_error 'Key cannot be nil'
    end

    it "errs if key is not valid" do
      expect do
        Cipher.new 123
      end.to raise_error 'Unsupported key 123'
    end

    key_size = 1024

    context "with a source file" do
      delete = Proc.new do |file|
        case file
        when String
          filename = file
        when File, IO
          filename = file.path
        end
        File.delete filename if File.exist? filename
      end

      bigfile = Tempfile.new('bigfile')
      bigfile.write(SecureRandom.hex) until bigfile.length > key_size * 16
      bigfile.close
      source = bigfile.path
      source_md5 = Digest::MD5.digest File.read(source)

      context "with a DSA keypair" do
        keypair = OpenSSL::PKey::DSA::new 1024

        it "fails to build" do
          expect do
            Cipher.new keypair
          end.to raise_error 'DSA is not supported'
        end
      end

      context "with an ssh public and private key file" do
        pubkeyfile = File.join(File.dirname(__FILE__), 'id_rsa_test.pub')
        privkeyfile = File.join(File.dirname(__FILE__), 'id_rsa_test')

        it "reads the key if it is an already open file" do
          File.open pubkeyfile, 'r' do |f|
            crypto = Cipher.new f
            crypto.pkey.should_not.nil?
          end
        end

        it "contains a valid key" do
          crypto = Cipher.new pubkeyfile
          crypto.pkey.should_not.nil?
        end

        it "encrypts and then decrypts a file correctly" do
          encrypter = Cipher.new pubkeyfile
          decrypter = Cipher.new privkeyfile
          source = bigfile.path
          encrypted = Dir::Tmpname::make_tmpname 'encrypted_big_file', nil
          decrypted = Dir::Tmpname::make_tmpname 'decrypted_big_file', nil

          begin
            encrypter.send :encrypt, source, encrypted
            encrypted_md5 = Digest::MD5.digest File.read(encrypted)
            source_md5.should_not eq encrypted_md5

            decrypter.decrypt(encrypted, decrypted)
            decrypted_md5 = Digest::MD5.digest File.read(decrypted)
            decrypted_md5.should eq source_md5
          ensure
            delete.call encrypted
            delete.call decrypted
          end

        end
      end

      context "with a generated RSA keypair" do
        keypair = OpenSSL::PKey::RSA::new key_size

        it "contains the key" do
          crypto = Cipher.new keypair
          crypto.pkey.should eq keypair
        end

        context "written to a temporary file" do
          keyfile = Tempfile.new('keypair')
          keyfile.write(keypair.to_pem)
          keyfile.write(keypair.public_key.to_pem)
          keyfile.close
          crypto = Cipher.new keyfile.path

          it "encrypts and then decrypts a file correctly" do
            source = bigfile.path
            encrypted = Dir::Tmpname::make_tmpname 'encrypted_big_file', nil
            decrypted = File.open(Dir::Tmpname::make_tmpname('decrypted_big_file', nil), 'w')

            begin
              crypto.send :encrypt, source, encrypted
              encrypted_md5 = Digest::MD5.digest File.read(encrypted)
              source_md5.should_not eq encrypted_md5

              crypto.decrypt(encrypted, decrypted)
              decrypted_md5 = Digest::MD5.digest File.read(decrypted)
              decrypted_md5.should eq source_md5
            ensure
              delete.call encrypted
              delete.call decrypted
            end
          end
        end
      end
    end
  end

  describe Key do

    it "can be read from an ssh file" do
    end

    it "should not be DSA" do
        keypair = OpenSSL::PKey::DSA::new 1024
        expect {
          Cipher.new keypair
        }.to raise_error 'DSA is not supported'
    end

  end

end
