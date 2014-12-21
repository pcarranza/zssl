require 'spec_helper'
require "tempfile"
require "zssl_options"

module Zoocial

  describe OptionsParser do
    it "is empty initially" do
      opts = OptionsParser.new
      opts.mode.should.nil?
      opts.source.should.nil?
      opts.target.should.nil?
      opts.key.should.nil?
    end

    context "parsing the input" do
      class OptionsParser
        def parse
          @options[:key] = File.join(File.dirname(__FILE__), 'id_rsa_test.pub')
        end
      end

      it "fails if no mode is passed" do
        opts = OptionsParser.new
        opts.stub(:arguments).and_return(nil)
        opts.stub(:puts)
        expect do opts.parse! end.to raise_error SystemExit
      end
      it "fails if invalid mode is passed" do
        opts = OptionsParser.new
        opts.stub(:arguments).and_return('invalid')
        opts.stub(:puts)
        expect do opts.parse! end.to raise_error SystemExit
      end
      it "encryption mode if e passed" do
        opts = OptionsParser.new
        opts.stub(:arguments).and_return('e')
        opts.parse!
        opts.mode.should eq :encrypt
      end
      it "decryption mode if d passed" do
        opts = OptionsParser.new
        opts.stub(:arguments).and_return('d')
        opts.parse!
        opts.mode.should eq :decrypt
      end
      it "points to ssh key if no key is provided" do
        opts = OptionsParser.new
        opts.stub(:arguments).and_return('d')
        opts.parse!
        opts.key.should end_with 'id_rsa_test.pub'
      end
      # it "points to the provided key" do
      #   private_rsa = File.join(File.dirname(__FILE__), 'id_rsa_test')
      #   keyopts = {:key => private_rsa}
      #   opts = OptionsParser.new
      #   opts.stub(:options).and_return(keyopts)
      #   opts.stub(:arguments).and_return('d')
      #   opts.parse!
      #   opts.key.should eq private_rsa
      # end
    #   it "fails if the provided key does not exists" do
    #     private_rsa = File.join(File.dirname(__FILE__), 'not_existing_key')
    #     keyopts = {:key => private_rsa}
    #     opts = OptionsParser.new
    #     opts.stub(:options).and_return(keyopts)
    #     opts.stub(:arguments).and_return('e')
    #     opts.stub(:puts)
    #     expect do opts.parse! end.to raise_error SystemExit
    #   end
    #   it "will use stdin and stdout if no source nor target is provided" do
    #     opts = OptionsParser.new
    #     opts.stub(:arguments).and_return('d')
    #     opts.parse!
    #     opts.source.should eq $stdin
    #     opts.target.should eq $stdout
    #   end
    #   it "will use source and target files as provided" do
    #     source = Tempfile.new('source')
    #     target = Tempfile.new('target')
    #     opts = OptionsParser.new
    #     opts.stub(:arguments).and_return('d')
    #     opts.parse!
    #     begin
    #       opts.source.should eq source
    #       opts.target.should eq target
    #     rescue
    #       File.delete source
    #       File.delete target
    #     end
    #   end
    end
  end

  describe "Options" do
    
    context "when creating" do
      it "fails without mode" do
        expect { Options.new }.to raise_error ArgumentError, "Mode is mandatory"
      end
      it "fails with an invalid mode" do
        expect { Options.new(:mode => "i") }.to raise_error ArgumentError, "Invalid mode"
      end
      # it "fails with enc as mode" do
      #   expect { Options.new(:mode => "enc") }.to raise_error ArgumentError, "Invalid mode"
      # end
      it "encrypts with e as mode" do
        expect(Options.new(:mode => "e").mode).to equal(:encrypt)
      end
      it "encrypts with encrypt as mode" do
        expect(Options.new(:mode => "encrypt").mode).to equal(:encrypt)
      end

      context 'encryption, by default' do
        let!(:by_default) { Options.new(:mode => "e") }
        it 'uses stdin as source' do
          expect(by_default.source).to equal(:stdin)
        end
        it 'uses stout as target' do
          expect(by_default.target).to equal(:stdout)
        end
        it 'uses ssh_id_rsa as key' do
          expect(by_default.key).to equal(:ssh_id_rsa)
        end
      end
    end


  end
end
