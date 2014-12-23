require "spec_helper"
require "open3"

describe "zssl executable acceptance testing" do

  it "Prints the help if no arguments are provided" do
    out = TestRunner.new.run
    raise "help option not found" unless out.include? "--help"
    raise "identity option not found" unless out.include? "--identity"
    raise "source argument not found" unless out.include? "source"
    raise "target argument not found" unless out.include? "target"
  end

  context "With a source file" do
    source = TestFiles.create_temporary_random_file
    encrypted = TestFiles.create_temporary_empty_file("encrypted")
    File.delete(encrypted)

    it "Encrypts a source file with the public key" do
      TestRunner.new(args=["encrypt", "-i#{TestRunner.public_key}", source, encrypted]).run

      fail "Encrypted file does not exists" unless File.exist?(encrypted)
      fail "Encrypted file is empty" if File.size(encrypted) == 0
    end

    it "Then decrypts the encrypted file with the private key and is equal to the source" do
      decrypted = TestFiles.create_temporary_empty_file("decrypted")
      File.delete(decrypted)

      TestRunner.new(args=["decrypt", "-i#{TestRunner.private_key}", encrypted, decrypted]).run

      fail "Decrypted file does not exists" unless File.exist?(decrypted)
      fail "Decrypted file is empty" if File.size(decrypted) == 0
      fail "Decrypted file is different than source" unless TestFiles.files_are_equal(source, decrypted)
    end
  end

  context "With another source file" do
    source = TestFiles.create_temporary_random_file
    encrypted = TestFiles.create_temporary_empty_file("encrypted")
    File.delete(encrypted)

    it "Encrypts a source file with the public key sending the file through stdin" do
      TestRunner.new(args=["e", "-i#{TestRunner.public_key}", '<', source]).run do |out, err|
        fail "There has been an error: #{err}" unless err.empty?
        fail "Encrypted output is empty" if out.empty?
        File.open(encrypted, 'w') do |f|
          f.write(out)
        end
      end
    end

    it "Then decrypts the encrypted file with the private key sending the file through stdin" do
      decrypted = TestFiles.create_temporary_empty_file("decrypted")
      File.delete(decrypted)
      TestRunner.new(args=["d", "-i#{TestRunner.private_key}", '<', encrypted, '>', decrypted]).run
      fail "Decrypted file does not exists" unless File.exist?(decrypted)
      fail "Decrypted file is empty" if File.size(decrypted) == 0
      fail "Decrypted file is different from source" unless TestFiles.files_are_equal(source, decrypted)
    end
  end
end

BEGIN {
  class TestRunner

    @@testdir = File.dirname(File.expand_path(__FILE__))
    @@rootdir = File.dirname(@@testdir)
    @@libdir = File.join(@@rootdir, "lib")

    def initialize(args=[])
      @command = [RbConfig.ruby, "--", "bin/zssl"] + args
    end

    def run
      rubyenv = ENV.clone
      rubyenv["RUBYLIB"] = @@libdir
      Open3.popen3(rubyenv, @command.join(' '), :chdir => @@rootdir) do |stdin, stdout, stderr, process|
        process.join
        out = stdout.read
        err = stderr.read
        if block_given?
          yield out, err
        else
          fail "Error: #{err}\nOutput: #{out}" unless err.empty?
          out
        end
      end
    end

    def self.private_key
      File.join(@@testdir, "id_rsa_test")
    end

    def self.public_key
      File.join(@@testdir, "id_rsa_test.pub")
    end
  end
}
