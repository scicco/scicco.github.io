---
layout: post
title:  "When the customer says: \"I need a Download Report button\""
date:   2017-05-16 13:30:00 +0200
category: [Ruby,Rails]
tags: [ruby,rails]
---
# {{ page.title }}
{:.no_toc}


### Table Of Contents
{:.no_toc}

* Table Of Contents
{:toc}

# A bad story 

Sometimes the user needs to schedule a complex report generation and download it once ready.

Putting this into a "user story" fashion it will become:

> as logged **User** i want to generate a monthly **report** and **dowload** it.

This simple scenario hides several problems:

- UX problem
- Request timeout
- Scheduling a long running task
- Persisting the generated content
- Making the content available
- Setup ACL on the content
- Disk space of the system

You can't let a user click a button and let him waiting five minutes or more to get the generated file, because he will have a bad user experience and probably will see a timeout error instead. He will eventually start hating and cursing you.. :rage:  

# The true story

We need to find another way to accomplish this task. We could try splitting it in separate phases.

Lets' reformulate the previous "user story"

> as logged **User** i want to provide a **one-time only password** and generate a monthly **report**. <br/>
> I want to receive an **email** with detailed instruction explaining how to **download the archive**.<br/> 
> I want to visit the URL inside the email, insert the previous password and download the archive.<br/>
> The **archive** must be deleted after two hours.

The new phases are:

- Report generation
- Email delivery
- Report Download
- Report cleanup

Now we need to have new "actors" on the main stage.

- A job to generate the report, we will call it `ReportExporterWorker`
- A Mailer to send email with download instruction, we will call it `ReportMailer`
- A controller used to check user ACL and serve the report, we will call it `ReportsController`
- A job used to cleanup the report after two hours, we will call it `ReportExportCleaner`

Now we can try addressing all the previous problems.


# Ruby Environment

The application and gems used in this post are:

- Ruby on Rails 3.x
- Devise Gem
- Sidekiq Gem

# Routes

We need to add some new routes inside `route.rb` file.

{% highlight ruby %}
scope 'reports' do
  get '/downloads', controller: 'reports', action: 'index'
  post '/generate', controller: 'reports', action: 'generate', as: :generate
  get '/downloads/:id/decode', controller: 'reports', action: 'decode', as: :decode
  post '/downloads', controller: 'reports', action: 'download', as: :download
end
{% endhighlight %}

# Index route

The first route is used to display a form with the email field inside.
{% highlight ruby %}
scope 'reports' do
  get '/downloads', controller: 'reports', action: 'index'
end
{% endhighlight %}

This is the `index` action inside the `ReportsController`
{% highlight ruby %}
def index
  @download = DownloadRequest.new
end
{% endhighlight %}

The form will show two fields. The email will be filled with the User's email but will be editable to allow the use of a different one.

The password is used to make data unreadable by others.

Here the form's part of the view:

{% highlight haml %}
= simple_form_for @download, url: generate_path, html: { autocomplete: 'off', role: 'presentation' } do |f|
  .form-inputs{style: 'margin-top: 50px'}
    = f.input :email, input_html: {value: current_user.email}
    = f.input :password, type: :password, input_html: {autocomplete: 'off'}
    %div.control-group
      %div.controls
        %p
          %strong
            please provide set a one-time only password used to encrypt sensitive data
    .actions
    - if request.xhr?
      = f.button :wrapped, :cancel => "#"
    - else
      = f.button :wrapped, :value => 'Send email with archive link'
{% endhighlight %}


This is the `DownloadRequest` object used inside the form and controller (@download). It's PORO object plus the methods needed to be used inside a form and some validation rules for its fields.

{% highlight ruby %}
class DownloadRequest
  extend ActiveModel::Naming
  include ActiveModel::Conversion
  include ActiveModel::Validations

  attr_accessor :email
  attr_accessor :password

  validates :email, presence: true, format: /\w+@\w+\.{1}[a-zA-Z]{2,}/
  validates :password, presence: true, length: 8..120

  def persisted?
    false
  end
  
  def new_record?
    true
  end
end
{% endhighlight %}


# Generate route

The second route is triggered with the click on submit button inside the previous form.  

{% highlight ruby %}
scope 'reports' do
  post '/generate', controller: 'reports', action: 'generate', as: :generate
end
{% endhighlight %}


## Generate action

The generate action inside the `ReportsController` initialize a new `DownloadRequest` object with the request's parameters and perform the validation
on email and password field. 

{% highlight ruby %}
def generate
  @download = DownloadRequest.new
  @download.email = params[:download_request][:email]
  @download.password = params[:download_request][:password]
  ...
{% endhighlight %}

If everything is ok a new `ReportExporterWorker` job will be scheduled.

{% highlight ruby %}
...
if @download.valid?
  ReportExporterWorker.perform_async(@download.email, @download.password)
  ...
{% endhighlight %}


This is the `generate` action inside the `ReportsController`

ReportExporterWorker

{% highlight ruby %}
def generate
  @download = DownloadRequest.new
  @download.email = params[:download_request][:email]
  @download.password = params[:download_request][:password]
  if @download.valid?
    ReportExporterWorker.perform_async(@download.email, @download.password)
    redirect_to root_path, notice: 'Check your email.'
  else
    flash[:error] = 'Email is invalid'
    render :index
  end
end
{% endhighlight %}


## Generate the report

The `ReportExporterWorker` has several steps into his `perform` method. Let's dive into it.


## Scheduling the job

First we can create a Sidekiq job to handle the report creation. This job create a new file under `"#{Rails.root}/tmp/reports"` folder.

The `perform` method will invoke the `LastMonthReportGenerator`, a service used to generate the report.

{% highlight ruby %}
now_formatted = Time.now.strftime('%Y%m%d%H%M')
report_file_name = "#{now_formatted}_report.csv"
report_file = File.join(Rails.root, 'tmp', 'reports', report_file_name)
report_result = LastMonthReportGenerator.new(report_file_name).generate
{% endhighlight %}


When the file is created we compress it to lower the size. 

{% highlight ruby %}
if report_result
  compressed_file_path = File.join(Rails.root, 'tmp', 'reports', "#{report_file_name}.gz")
  Zlib::GzipWriter.open(compressed_file_path) do |gz|
    gz.orig_name = "#{report_file_name}.gz"
    gz.mtime = File.mtime(report_file)
    gz.write IO.binread(report_file)
    gz.close
  end
{% endhighlight %}


## Sending the content

Now we have a compressed file. 

We setup the data that will be crypted. 

{% highlight ruby %}
payload = PayloadBuilder.compose_data(compressed_file_path)
{% endhighlight %}

We crypt the expiration and the file path with `DownloadEncrypter`.

{% highlight ruby %}
archive_path_for_mail = DownloadEncrypter.encrypt(payload, password)
{% endhighlight %}

The encoded path is passed to `ReportMailer` mailer. The email contains the URL needed to download the report.

{% highlight ruby %}
ReportMailer.notification(archive_path_for_mail, email).deliver!
{% endhighlight %}


The Mailer is pretty simple. It pick the path and email from the argument and deliver the email.

Full `ReportMailer` source code:

{% highlight ruby %}
class ReportMailer < ActionMailer::Base
  default from: 'admin@evilcorp.com'
  
  def notification(file_path, email)
    @path = report_download_url(file_path)
    mail(subject: "Report Generated at: #{Time.now}", :to => email)
  end
end
{% endhighlight %}

and the email template

{% highlight erb %}
<H3>Here you will find your Report</H3>

click <%= link_to 'here', @path %> to Download the archive.

<p>Please note the that the link will be accessible only for 2 hours. After that period the file will be removed.</p>

<p>Kind Regards</p>

<p>Evil Corp<br/>
{% endhighlight %}


## Cleanup our system

After the email delivery we'll schedule another job named `ReportExportCleaner`. It's responsible for the report file deletion from the system. 

{% highlight ruby %}
ReportExportCleaner.perform_at(2.hours.from_now, File.basename(compressed_file_path, '.gz'))
{% endhighlight %}

We also delete the uncompressed report file from system.

{% highlight ruby %}
File.delete(report_file)
{% endhighlight %}

Full `ReportExporterWorker` source code:

{% highlight ruby %}
require 'yaml'
require 'zlib'
 
class ReportExporterWorker
  include Sidekiq::Worker

  sidekiq_options backtrace: true, queue: :reports, unique: :until_executed

  def perform(email, password)
    now_formatted = Time.now.strftime('%Y%m%d%H%M')
    report_file_name = "#{now_formatted}_report.csv"
    report_file = File.join(Rails.root, 'tmp', 'reports', report_file_name)
    report_result = LastMonthReportGenerator.new(report_file_name).generate
    if report_result
      compressed_file_path = File.join(Rails.root, 'tmp', 'reports', "#{report_file_name}.gz")
      Zlib::GzipWriter.open(compressed_file_path) do |gz|
        gz.orig_name = "#{report_file_name}.gz"
        gz.mtime = File.mtime(report_file)
        gz.write IO.binread(report_file)
        gz.close
      end
      payload = PayloadBuilder.compose_data(compressed_file_path)
      archive_path_for_mail = DownloadEncrypter.encrypt(payload, password)
      ReportMailer.notification(archive_path_for_mail, email).deliver!
      ReportExportCleaner.perform_at(2.hours.from_now, File.basename(compressed_file_path, '.csv.gz'))
      File.delete(report_file)
    end
  end
end
{% endhighlight %}

## Avoid leaking sensitive data

In this scenario we don't use any external storage service, we just save the report in a temporary folder.

We don't persist any report information into our database, so we need a way to pass the archive's path between each step.

`PayloadBuilder` will help us to create a data with the following information:
- report expiration
- report file path

The expiration will be within two hours after the report creation.

The file path is taken from the argument.

The `extract_expiration` the `extract_path` methods do the opposite.

Full `PayloadBuilder` source code:

{% highlight ruby %}
require 'base64'
class PayloadBuilder

  TIME_FORMAT = "%Y-%m-%d-%R%z"
  
  def self.compose_data(data)
    expiration = 2.hours.from_now.utc.strftime(TIME_FORMAT)
    payload = expiration + '|' + data
    Base64.urlsafe_encode64(payload)
  end
  
  def self.extract_expiration(data)
    raise ArgumentError if data.nil? || data.index('|').nil?
    separator_index = data.index('|')
    expiration_raw = data[0..separator_index-1]
    expiration = expiration_raw[0..expiration_raw.size]
    Time.strptime(expiration, TIME_FORMAT)
  end
  
  def self.extract_path(data)
    raise ArgumentError if data.nil? || data.index('|').nil?
    separator_index = data.index('|')
    data[separator_index+1..data.size]
  end
end
{% endhighlight %}


`DownloadEncrypter` will encrypt/decrypt our data:

It uses **AES 256 GCM** to make our data safe.

Here you can find some details about it:

- ["aes256 gcm can someone explain how to use it securely ruby" on crypto.stackexchange.com](https://crypto.stackexchange.com/questions/17999/aes256-gcm-can-someone-explain-how-to-use-it-securely-ruby){:target="_blank"}
- [Galois Counter Mode on Wikipedia](https://en.wikipedia.org/wiki/Galois/Counter_Mode){:target="_blank"}

The encrypt method will return the combination of **IV** + _separator_ + **our_secret_data** + _separator_ + **tag** in Base64

The decrypt method perform decode the Base64, then split the result by the _separator_ and collect each needed piece of information to decrypt our data.

Full `DownloadEncrypter` source code:

{% highlight ruby %}
class DownloadEncrypter
  def self.bin2hex(str)
    str.unpack('C*').map {|b| "%02X" % b}.join('')
  end
  
  def self.hex2bin(str)
    [str].pack "H*"
  end

  def self.encrypt(payload, password)
    cipher = OpenSSL::Cipher::Cipher.new('aes-256-gcm')
    cipher.encrypt
    salt = hex2bin('SOME VERY VERY LONG string Used As salt to be safe. ')
    key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(password, salt, 20000, cipher.key_len)
    cipher.key = key
    iv = cipher.random_iv
    cipher.iv = iv
    cipher.auth_data = ''
    encrypted_binary = cipher.update(payload) + cipher.final
    tag = cipher.auth_tag
    secret = Base64.urlsafe_encode64(bin2hex(iv) + bin2hex('$$$$$') + bin2hex(encrypted_binary) + bin2hex('$$$$$') + bin2hex(tag))
    secret
  end

  def self.decrypt(encrypted_payload, password)
    raw_data_array = Base64.urlsafe_decode64(encrypted_payload)
    raw_data = raw_data_array.split(bin2hex('$$$$$'))
    iv = hex2bin(raw_data[0])
    data = hex2bin(raw_data[1])
    tag = hex2bin(raw_data[2])
    salt = hex2bin('SOME VERY VERY LONG string Used As salt to be safe. ')
    
    cipher = OpenSSL::Cipher::Cipher.new('aes-256-gcm')
    cipher.decrypt
    key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(password, salt, 20000, cipher.key_len)
    cipher.key = key
    cipher.iv = iv
    cipher.auth_tag = tag
    cipher.auth_data = ''
    plaintext = cipher.update(data) + cipher.final
    plaintext
  end
end
{% endhighlight %}

## Report cleanup

`ReportExportCleaner` will delete the report from our system. The `perform` method receive a `file_name` as argument. 

### Sanitize the argument
{:.no_toc}

This job could be exploited by malicious users trying passing path argument like `'../../..some_file_name'` and deceiving the job and deleting file into our system so we had to find a way to sanitize the argument. 

#### First step
{:.no_toc}

The first step is checking if the file_name is valid. 

{% highlight ruby %}
unless is_valid?(file_name)
  message = "wrong file_name argument: #{file_name}"
  logger.error(message)
  return
end
{% endhighlight %}

This is accomplished by `sanitize_file_name` method called inside `is_valid?`

{% highlight ruby %}
def is_valid?(file_name)
  sanitize_file_name(file_name.dup) == file_name
end
{% endhighlight %}

The `sanitize_file_name` method was taken from this [blog post](http://gavinmiller.io/2016/creating-a-secure-sanitization-function/) 
of [Gavin Miller](https://twitter.com/gavingmiller) (@gavin_miller). 

I decide to use both whitelist and blacklist approach. To do this, I only use the basename of file without the extension part as argument (the . character is not allowed in the whitelist).

{% highlight ruby %}
def sanitize_file_name(file_name)
  # WHITELIST APPROACH
  # Remove any character that aren't 0-9, A-Z, or a-z
  file_name.gsub!(/[^0-9A-Z]/i, '_')

  # BLACKLIST APPROACH
  # Bad as defined by wikipedia: https://en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
  # Also have to escape the backslash
  bad_chars = ['/', '\\', '?', '%', '*', ':', '|', '"', '<', '>', '.', ' ']
  bad_chars.each do |bad_char|
    file_name.gsub!(bad_char, '_')
  end
  file_name
end
{% endhighlight %}


#### Second step
{:.no_toc}

The second step is checking if a file `"#{Rails.root}/tmp/reports/#{file_name}.gz"` exists (where file_name is the argument of perform).

{% highlight ruby %}
name_complete = File.join(Rails.root, 'tmp', 'reports', file_name + '.gz')
unless File.exist?(name_complete)
  message = "unable to found a valid file: #{name_complete}"
  raise ArgumentError.new(message)
end
{% endhighlight %}


If all the steps are ok we can safely delete the file.

{% highlight ruby %}
File.delete(name_complete)
{% endhighlight %}

Full `ReportExportCleaner` source code:

{% highlight ruby %}
class ReportExportCleaner
  include Sidekiq::Worker
  sidekiq_options backtrace: true, queue: :reports, unique: :until_executed
  
  def perform(file_name)
    unless is_valid?(file_name)
      message = "wrong file_name argument: #{file_name}"
      logger.error(message)
      return
    end
    
    name_complete = File.join(Rails.root, 'tmp', 'reports', file_name + '.gz')
    unless File.exist?(name_complete)
      message = "unable to found a valid file: #{name_complete}"
      raise ArgumentError.new(message)
    end
    
    File.delete(name_complete)
  end
  
  private
  
  def is_valid?(file_name)
    sanitize_file_name(file_name.dup) == file_name
  end
  
  def sanitize_file_name(file_name)
    # WHITELIST APPROACH
    # Remove any character that aren't 0-9, A-Z, or a-z
    file_name.gsub!(/[^0-9A-Z]/i, '_')
    
    # BLACKLIST APPROACH
    # Bad as defined by wikipedia: https://en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
    # Also have to escape the backslash
    bad_chars = ['/', '\\', '?', '%', '*', ':', '|', '"', '<', '>', '.', ' ']
    bad_chars.each do |bad_char|
      file_name.gsub!(bad_char, '_')
    end
    file_name
  end
  
  def logger
    @logger ||= begin
      log = File.open(File.join(Rails.root, 'log', 'malicius_calls.log'), "a")
      log.sync = true
      log
    end
  end
{% endhighlight %}

# Report download

The third route is triggered when the User click inside the report link inside the email.

{% highlight ruby %}
scope 'reports' do
  get '/downloads/:id/decode', controller: 'reports', action: 'decode', as: :decode
end
{% endhighlight %}



## Decode action

The action reads the `id` parameter and shows a view with a form containing a password field and an hidden field with the `id` inside.

{% highlight ruby %}
  def decode
    @download = Download.new
    @download.id = params[:id]
  end
{% endhighlight %}

The view lets the User input the previous password and click download to invoke the download action.

This is the view:

{% highlight haml %}
= simple_form_for @download, url: download_path, html: { autocomplete: 'off', role: 'presentation' } do |f|
  .form-inputs{style: 'margin-top: 50px'}
    %div.control-group
      %div.controls
        %p
          %strong
            Insert the archive password
    = f.input :password, input_html: {autocomplete: 'off', type: 'password'}
    = f.input :id, type: :hidden, input_html: {type: :hidden, autocomplete: 'off'}, label_html: {style: 'display: none'}
    .actions
      = f.button :wrapped, :value => 'Download'
{% endhighlight %}

## Download action

The last route is called after the User has submitted the form after filling it with the previous password.

{% highlight ruby %}
scope 'reports' do
  post '/downloads', controller: 'reports', action: 'download', as: :download
end
{% endhighlight %}


The action reads `id` and `password` parameter from the request and tries to decrypt it using `decrypt` method of `DownloadEncrypter`. 

After it will decode the base64 unencrypted data.

{% highlight ruby %}
def download
  @download = Download.new
  @download.id = params[:download][:id]
  @download.password = params[:download][:password]
  begin
    base64_data = DownloadEncrypter.decrypt(@download.id, @download.password)
    data = Base64.urlsafe_decode64(base64_data)
  rescue OpenSSL::Cipher::CipherError
    flash[:error] = 'password is wrong'
    render :decode
    return
  end
  ...
{% endhighlight %}

After it retrieves the expiration with `extract_expiration` method of `PayloadBuilder` and check for invalidation

{% highlight ruby %}
parsed_expiration = PayloadBuilder.extract_expiration(data)

if Time.now > parsed_expiration
  redirect_to root_path, status: :gone
  return
end

{% endhighlight %}

The last part retrieves the report path using `extract_path` of `PayloadBuilder` and use `send_file` to start the download.

{% highlight ruby %}
file_path = PayloadBuilder.extract_path(data)
send_file file_path
{% endhighlight %}

This is the `download` action inside the `ReportsController`

{% highlight ruby %}
  def download
    @download = Download.new
    @download.id = params[:download][:id]
    @download.password = params[:download][:password]
    begin
      begin
        base64_data = DownloadEncrypter.decrypt(@download.id, @download.password)
        data = Base64.urlsafe_decode64(base64_data)
      rescue OpenSSL::Cipher::CipherError
        flash[:error] = 'password is wrong'
        render :decode
        return
      end
      parsed_expiration = PayloadBuilder.extract_expiration(data)
      
      if Time.now > parsed_expiration
        redirect_to root_path, status: :gone
        return
      end
      
      file_path = PayloadBuilder.extract_path(data)
      send_file file_path
    rescue ArgumentError
      redirect_to root_path, status: :unprocessable_entity, alert: 'something went wrong'
      return
    rescue  ActionController::MissingFile
      redirect_to root_path, status: :not_found, alert: 'archive not found'
      return
    end
  end  
{% endhighlight %}

This is the `Download` object used inside the form and `ReportsController`'s `download` method. 
It's PORO object plus the methods needed to be used inside a form and some validation rules for his fields.

{% highlight ruby %}
class Download
  extend ActiveModel::Naming
  include ActiveModel::Conversion
  include ActiveModel::Validations

  attr_accessor :password
  attr_accessor :id

  validates :password, presence: true

  def persisted?
    false
  end
  
  def new_record?
    true
  end
end
{% endhighlight %}


# Authorization

We use Devise's directive to check authorizations on each action:

{% highlight ruby %}
before_filter :authenticate_user!
{% endhighlight %}



Full `ReportsController` source code:

{% highlight ruby %}
class ReportsController < ApplicationController
  before_filter :authenticate_user!
  
  def index
    @download = DownloadRequest.new
  end
   
  def generate
    @download = DownloadRequest.new
    @download.email = params[:download_request][:email]
    @download.password = params[:download_request][:password]
    if @download.valid?
      ReportExporterWorker.perform_async(@download.email, @download.password)
      redirect_to root_path, notice: 'Check your email.'
    else
      render :index
    end
  end

  def decode
    @download = Download.new
    @download.id = params[:id]
  end

  def download
    @download = Download.new
    @download.id = params[:download][:id]
    @download.password = params[:download][:password]
    begin
      begin
        base64_data = DownloadEncrypter.decrypt(@download.id, @download.password)
        data = Base64.urlsafe_decode64(base64_data)
      rescue OpenSSL::Cipher::CipherError
        flash[:error] = 'password is wrong'
        render :decode
        return
      end
      parsed_expiration = PayloadBuilder.extract_expiration(data)
      
      if Time.now > parsed_expiration
        redirect_to root_path, status: :gone
        return
      end
      
      file_path = PayloadBuilder.extract_path(data)
      send_file file_path
    rescue ArgumentError
      redirect_to root_path, status: :unprocessable_entity, alert: 'something went wrong'
      return
    rescue  ActionController::MissingFile
      redirect_to root_path, status: :not_found, alert: 'archive not found'
      return
    end
  end
end
{% endhighlight %}


# Final thoughts

There is still space for improvements.

My solution is far from being the best way to address this task, but I hope it is a starting point to help you tackling this problem.

There are several topics that i'd like to improve which may be subject of next blog posts.

## Strong Parameters
{:.no_toc}

You should use strong parameters to validate the params inside each controller action. This example is based on an old application that needs to be updated.
 
If you have a similar scenario this [answer](http://stackoverflow.com/a/14252971/1488217){:target="_blank"} could be a starting point.

## Filename sanitization
{:.no_toc}

I'm not sure about this solution. I fear there are additional ways to circumvent the checks done. 

## Initialization vector into our data
{:.no_toc}

I had some doubts about putting components such as the initialization vector (IV) inside our output but, according to this [answer](https://security.stackexchange.com/a/49033/34551){:target="_blank"}, it should be legit.
 
# Waiting for your feedbacks
{:.no_toc}

Thanks for reading up here. 

I'd like to hear some suggestions from you about my solution.