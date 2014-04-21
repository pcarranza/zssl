require "openssl"
require_relative '../encrypt.rb'

describe Encrypter do
    it "raises ArgumentError without public key" do
        expect do 
            Encrypter.new nil 
        end.to raise_error(ArgumentError)
    end

    context "with a keypair" do
        keypair = OpenSSL::PKey::RSA::new 1024
        encrypter = Encrypter.new keypair

        it "contains the key" do
            encrypter.key.should_not.nil?
        end
        it "raises ArgumentError encrypting empty text" do
            expect do
                encrypter.encrypt ""
            end.to raise_error(ArgumentError)
        end
        it "raises ArgumentError encrypting nil text" do
            expect do
                encrypter.encrypt nil 
            end.to raise_error(ArgumentError)
        end
        it "encrypts a text smaller than the key" do
            crypto = encrypter.encrypt "some text"
            crypto.should_not.nil?
        end
        it "fails to encrypt text bigger than the key" do
            expect do
                encrypter.encrypt "a" * 2048
            end.to raise_error(OpenSSL::PKey::RSAError)
        end
    end
end
