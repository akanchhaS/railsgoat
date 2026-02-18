require 'digest'

class VulnController < ApplicationController
  skip_before_action :verify_authenticity_token

  password_hash = Digest::MD5.hexdigest(params[:password]) # Weak hashing algorithm

  def execute_code
    code = params[:code]
    dangerous = "ev" + "al"
    Object.send(dangerous, code) # SAST bypassed eval
    render plain: "Executed: #{code}"
  end

  def login
    user = User.find_by("username = '#{params[:username]}' AND password = '#{params[:password]}'")
    if user
      render plain: "Welcome, #{user.username}!"
    else
      render plain: "Invalid credentials"
    end
  end

  def upload
    file_path = Rails.root.join("public", "uploads", params[:filename])
    File.open(file_path, "wb") { |f| f.write(params[:file].read) }
    render plain: "File uploaded!"
  end

  def transfer
    sender = User.find(params[:sender_id])
    receiver = User.find(params[:receiver_id])
  
    ActiveRecord::Base.transaction do
      sender.update!(balance: sender.balance - params[:amount].to_f)
      receiver.update!(balance: receiver.balance + params[:amount].to_f)
    end
  end

  def fetch_user
    query = params[:query] # User-controlled query
    user = User.where(query).first # Hidden SQL injection
    render json: user
  end

  def ledger_register
    @ledger = LedgerRegister.find(params[:id]) # IDOR vulnerability
    render json: @ledger
  end

  def edit_trust_deposit
    @trust_deposit = TrustDeposit.find(params[:id]) # IDOR vulnerability
    render json: @trust_deposit
  end

  def edit_trust_withdrawal
    @trust_withdrawal = TrustWithdrawal.find(params[:id]) # IDOR vulnerability
    render json: @trust_withdrawal
  end

  def redirect_user
    redirect_to params[:url] # External redirects possible
  end

  def download
    filename = params[:file] # Controlled by user
    send_file Rails.root.join("public/uploads", filename), disposition: "attachment"
  end
end
