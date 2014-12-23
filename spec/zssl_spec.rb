require "spec_helper"
require "zssl"
require "digest/md5"

module Zoocial

  describe Cipher do

    it "errs when initializing without a key" do
      expect {
        Cipher.new nil
      }.to raise_error "A key is required"
    end
    it "errs when initializing with a DSA keypair" do
      keypair = OpenSSL::PKey::DSA::new 1024
      expect {
        Cipher.new keypair
      }.to raise_error "DSA is not supported"
    end

    context "with a pair of ssh key files" do
      let!(:ssh_id_rsa) { File.join(File.dirname(__FILE__), "id_rsa_test") }
      let!(:ssh_id_rsa_pub) { "#{ssh_id_rsa}.pub" }

      it "initializes with an ssh public key from a file path" do
        cipher = Cipher.new ssh_id_rsa_pub
        cipher.pkey.should_not.nil?
      end
      it "initializes with an ssh public key from an open file object" do
        File.open ssh_id_rsa_pub, "r" do |f|
          cipher = Cipher.new f
          cipher.pkey.should_not.nil?
        end
      end

      source = TestFiles.create_temporary_random_file
      source_md5 = get_file_md5(source)
      encrypted = TestFiles.create_temporary_empty_file(:name => "encrypted")

      it "encrypts a source file correctly using the public key" do
        cipher = Cipher.new ssh_id_rsa_pub
        cipher.encrypt(source, encrypted)
        source_md5.should_not eq get_file_md5(encrypted)
      end
      it "then decrypts the encrypted file correctly using the private key and the file matches the source" do
        decrypted = TestFiles.create_temporary_empty_file(:name => "decrypted")
        decipher = Cipher.new ssh_id_rsa
        decipher.decrypt(encrypted, decrypted)
        source_md5.should eq get_file_md5(decrypted)
      end
    end

    context "with a newly generated RSA openssl key object" do
      keypair = OpenSSL::PKey::RSA::new 1024
      fingerprint = get_fingerprint(keypair.public_key)

      it "initializes with the RSA keypair object" do
        cipher = Cipher.new keypair
        fingerprint.should eq get_fingerprint(cipher.pkey.public_key)
      end

      it "initializes with the RSA keypair written to a file" do
        keyfile = File.open(TestFiles.create_temporary_empty_file(:name => "keypair"), "w") do |file|
          file.write(keypair.to_pem)
          file.write(keypair.public_key.to_pem)
          file.close
          file.path
        end
        cipher = Cipher.new keyfile
        fingerprint.should eq get_fingerprint(cipher.pkey.public_key)
      end

      source = TestFiles.create_temporary_random_file
      source_md5 = get_file_md5(source)
      encrypted = TestFiles.create_temporary_empty_file(:name => "encrypted")

      it "encrypts a file correctly" do
        cipher = Cipher.new keypair
        cipher.encrypt(source, encrypted)
        source_md5.should_not eq get_file_md5(encrypted)
      end
      it "then decrypts the encrypted file correctly and matches the source" do
        decrypted = File.open(TestFiles.create_temporary_empty_file(:name => "decrypted"), "w")

        cipher = Cipher.new keypair
        cipher.decrypt(encrypted, decrypted)
        source_md5.should eq get_file_md5(decrypted)
      end
    end
  end

  describe SSHKey do

    it "errs without a file" do
      expect { SSHKey.new }.to raise_error(ArgumentError, "File is required")
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

    it "can load a pub key from a pub file" do
      sshkey = SSHKey.new(:file => ssh_id_rsa_pub)
      expect(sshkey.rsa.e.to_s).to eq(pub_e)
      expect(sshkey.rsa.n.to_s).to eq(pub_n)
    end

    it "can load a private key from a file" do
      sshkey = SSHKey.new(:file => ssh_id_rsa)
      expect(sshkey.rsa.e.to_s).to eq(pub_e)
      expect(sshkey.rsa.n.to_s).to eq(pub_n)
    end

  end

end
