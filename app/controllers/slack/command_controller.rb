require 'openssl'
require 'active_support/security_utils'
class Slack::CommandController < ApplicationController
  skip_before_action :verify_authenticity_token
  before_action :verify_slack_request, only: [:create]
  def create
    json = {
        "text": "Would you like to play a game?",
        "attachments": [
            {
                "text": "Choose a game to play",
                "fallback": "You are unable to choose a game",
                "callback_id": "wopr_game",
                "color": "#3AA3E3",
                "attachment_type": "default",
                "actions": [
                    {
                        "name": "game",
                        "text": "Chess",
                        "type": "button",
                        "value": "chess"
                    },
                    {
                        "name": "game",
                        "text": "Falken's Maze",
                        "type": "button",
                        "value": "maze"
                    },
                    {
                        "name": "game",
                        "text": "Thermonuclear War",
                        "style": "danger",
                        "type": "button",
                        "value": "war",
                        "confirm": {
                            "title": "Are you sure?",
                            "text": "Wouldn't you prefer a good game of chess?",
                            "ok_text": "Yes",
                            "dismiss_text": "No"
                        }
                    }
                ]
            }
        ]
    }
    render json: json
  end

  def bot
    message = params[:text].gsub(params[:trigger_word], '').strip
    repo = message.split('_').map {|c| c.strip.downcase }.last
    repo_url = "https://api.github.com/repos/#{repo}"
    resp = HTTParty.get(repo_url)
    resp = JSON.parse resp.body

    json = {
        "text": "There are #{resp['open_issues_count']} open issues on #{repo}"
    }
    render json: json
  end

  private

  def verify_slack_request
    timestamp = request.headers['X-Slack-Request-Timestamp']
    if (Time.now.to_i - timestamp.to_i).abs > 60 * 5
      head :unauthorized
      return
    end

    sig_basestring = "v0:#{timestamp}:#{request.raw_post}"
    signature = "v0=" + OpenSSL::HMAC.hexdigest("SHA256", ENV['SLACK_SIGNING_SECRET'], sig_basestring)
    slack_signature = request.headers['X-Slack-Signature']
    unless ActiveSupport::SecurityUtils.secure_compare(signature, slack_signature)
      head :unauthorized
    end
  end
end