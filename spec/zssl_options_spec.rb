require 'spec_helper'
require "tempfile"
require "zssl_options"

Options = Zoocial::Options

describe Options do
    it "is empty initially" do
        opts = Options.new
        opts.mode.should.nil?
        opts.source.should.nil?
        opts.target.should.nil?
        opts.key.should.nil?
    end
    it "points to the ssh rsa key by default" do
        opts = Options.new
        opts.local_ssh_key.should end_with ".ssh/id_rsa"
    end

    context "parsing the input" do
        local_rsa = File.join(File.dirname(__FILE__), 'id_rsa_test.pub')
        class Zoocial::Options
            def parse
            end
        end

        it "fails if no mode is passed" do
            opts = Options.new
            opts.stub(:arguments).and_return(nil)
            opts.stub(:puts)
            expect do opts.parse! end.to raise_error SystemExit
        end
        it "fails if invalid mode is passed" do
            opts = Options.new
            opts.stub(:arguments).and_return('invalid')
            opts.stub(:puts)
            expect do opts.parse! end.to raise_error SystemExit
        end
        it "encryption mode if e passed" do
            opts = Options.new
            opts.stub(:arguments).and_return('e')
            opts.stub(:local_ssh_key).and_return local_rsa
            opts.parse!
            opts.mode.should eq :encrypt
        end
        it "decryption mode if d passed" do
            opts = Options.new
            opts.stub(:arguments).and_return('d')
            opts.stub(:local_ssh_key).and_return local_rsa
            opts.parse!
            opts.mode.should eq :decrypt
        end
        it "points to ssh key if no key is provided" do
            opts = Options.new
            opts.stub(:arguments).and_return('d')
            opts.stub(:local_ssh_key).and_return local_rsa
            opts.parse!
            opts.key.path.should eq local_rsa
        end
        it "fails if no key provided nor ssh key is available" do
            opts = Options.new
            opts.stub(:arguments).and_return('e')
            opts.stub(:local_ssh_key).and_return ''
            opts.stub(:puts)
            expect do opts.parse! end.to raise_error SystemExit
        end
        it "points to the provided key" do
            private_rsa = File.join(File.dirname(__FILE__), 'id_rsa_test')
            keyopts = {:key => private_rsa}
            opts = Options.new
            opts.stub(:options).and_return(keyopts)
            opts.stub(:arguments).and_return('d')
            opts.parse!
            opts.key.path.should eq private_rsa
        end
        it "fails if the provided key does not exists" do
            private_rsa = File.join(File.dirname(__FILE__), 'not_existing_key')
            keyopts = {:key => private_rsa}
            opts = Options.new
            opts.stub(:options).and_return(keyopts)
            opts.stub(:arguments).and_return('e')
            opts.stub(:puts)
            expect do opts.parse! end.to raise_error SystemExit
        end
        it "will use stdin and stdout if no source nor target is provided" do
            opts = Options.new
            opts.stub(:arguments).and_return('d')
            opts.stub(:local_ssh_key).and_return local_rsa
            opts.parse!
            opts.source.should eq $stdin
            opts.target.should eq $stdout
        end
        it "will use source and target files as provided" do
            source = Tempfile.new('source')
            target = Tempfile.new('target')
            opts = Options.new
            opts.stub(:arguments).and_return('d')
            opts.stub(:local_ssh_key).and_return local_rsa
            opts.parse!
            begin
                opts.source.should eq source
                opts.target.should eq target
            rescue
                File.delete source
                File.delete target
            end
        end
    end
end

