require "spec_helper"
require "zssl"
require "digest/md5"

module Zoocial

  describe Cipher do

    let!(:ssh_id_rsa) { File.join(File.dirname(__FILE__), "id_rsa_test") }
    let!(:ssh_id_rsa_pub) { "#{ssh_id_rsa}.pub" }

    it "errs when building without a key" do
      expect do
        Cipher.new nil
      end.to raise_error "Key is required"
    end

    it "fails to build with a DSA keypair" do
      keypair = OpenSSL::PKey::DSA::new 1024
      expect do
        Cipher.new keypair
      end.to raise_error "DSA is not supported"
    end

    context "with a source file" do
      source = TestFiles.create_temporary_random_file
      source_md5 = Digest::MD5.digest(File.open(source, "r").read())

      context "with an ssh public and private key file" do

        it "reads the key if it is an already open file" do
          File.open ssh_id_rsa_pub, "r" do |f|
            crypto = Cipher.new f
            crypto.pkey.should_not.nil?
          end
        end

        it "contains a valid key" do
          crypto = Cipher.new ssh_id_rsa_pub
          crypto.pkey.should_not.nil?
        end

        encrypted = TestFiles.create_temporary_empty_file(:name => "encrypted")
        decrypted = TestFiles.create_temporary_empty_file(:name => "decrypted")

        it "encrypts a file correctly" do
          cipher = Cipher.new ssh_id_rsa_pub
          cipher.encrypt(source, encrypted)
          encrypted_md5 = Digest::MD5.digest File.read(encrypted)
          source_md5.should_not eq encrypted_md5
        end

        it "then decrypts the encrypted file correctly" do
          decipher = Cipher.new ssh_id_rsa
          decipher.decrypt(encrypted, decrypted)
          decrypted_md5 = Digest::MD5.digest File.read(decrypted)
          decrypted_md5.should eq source_md5
        end
      end

      context "with a generated RSA keypair" do
        keypair = OpenSSL::PKey::RSA::new 1024

        it "contains the key" do
          crypto = Cipher.new keypair
          crypto.pkey.should eq keypair
        end

        context "written to a file" do
          keyfile = File.open(TestFiles.create_temporary_empty_file(:name => "keypair"), "w") do |file|
            file.write(keypair.to_pem)
            file.write(keypair.public_key.to_pem)
            file
          end
          encrypted = TestFiles.create_temporary_empty_file(:name => "encrypted")

          crypto = Cipher.new keyfile.path

          it "encrypts a file correctly" do 
            crypto.send :encrypt, source, encrypted
            encrypted_md5 = Digest::MD5.digest File.read(encrypted)
            source_md5.should_not eq encrypted_md5
          end
          it "then decrypts the encrypted file correctly" do
            decrypted = File.open(TestFiles.create_temporary_empty_file(:name => "decrypted"), "w")
            crypto.decrypt(encrypted, decrypted)
            decrypted_md5 = Digest::MD5.digest File.read(decrypted)
            decrypted_md5.should eq source_md5
          end
        end
      end
    end
  end

  describe SSHKey do

    it "fails with error without a file" do
      expect { SSHKey.new }.to raise_error(ArgumentError, "Filename is required")
    end

    let!(:ssh_id_rsa) { File.join(File.dirname(__FILE__), "id_rsa_test") }
    let!(:ssh_id_rsa_pub) { "#{ssh_id_rsa}.pub" }

    let!(:pub_n) {
      "231069559501742444218495287675120846094965542347670961881052237776584769" +
      "273043668624017164461229096583758460385903092375272223124866737230529743" +
      "391897753729946928575322814441350866472309822306201685879129238700830269" +
      "120098986951793340195831462812435193501610102440803431706970319260319065" +
      "687679831285844568307139584323381230402680618161927195912301382030597144" +
      "202422011982456872146374607823063415991233659611776244257152140297061876" +
      "552894030061608120400967159375081006395931743477829014327328493979611701" +
      "183360797502215904549856594817444208311508839570137714704133620260352062" +
      "18011528297319868703374919652048692793521"
    }
    let!(:pub_e) { "65537" }

    it "can load a pub key from a file" do
      sshkey = SSHKey.new(:file => ssh_id_rsa_pub)
      expect(sshkey.rsa.e.to_s).to eq(pub_e)
      expect(sshkey.rsa.n.to_s).to eq(pub_n)
    end

    it "can load a priv key from a file" do
      sshkey = SSHKey.new(:file => ssh_id_rsa)
      expect(sshkey.rsa.e.to_s).to eq(pub_e)
      expect(sshkey.rsa.n.to_s).to eq(pub_n)
    end

  end

end
