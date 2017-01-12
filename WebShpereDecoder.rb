
VERSION         = '1.4 (beta)'
DEBUG           = true
APP_ID          = ''

# Ruby requires
require 'java'
require 'openssl'
# Java imports
java_import javax.swing.JOptionPane
# Burp imports
java_import 'burp.IBurpExtender'
java_import 'burp.IMessageEditorTabFactory'
java_import 'burp.IMessageEditorTab'
java_import 'burp.IRequestInfo'
java_import 'burp.IHttpRequestResponse'


module WebSphereHelper
  # include IRequestInfo
  include IHttpRequestResponse
  
  # TODO
  # Checks
  #   - Headers: one or more of
  #     Server:  WebSphere Application Server
  #     IBM-Web2-Location:
  #     X-Powered-By: Servlet/3.0
  #
  #   - URI
  #     [Res] | Content-Location: /wps/contenthandler/pps/!ut/p/xxxxxx
  #     [Req] | GET: /wps/contenthandler/pps/!ut/p/xxxxx
  #     [Res] | Location: https://www.xxxx/wps/portal/Home/Home/!ut/p/z1/
  #     [Req] | Referer: https://www.xxxx/wps/portal/Home/Home/!ut/p/z1/
  def web_sphere_url?(info, is_request, callbacks='')
    
    if is_request
      # info.methods.each {|m| callbacks.issueAlert("#{m.join("\n")}")}
      # callbacks.issueAlert(info.methods)
      
    end
    
  end
  
  
end

#
# BurpSuite GUI Factory
#

module GUI
  DISPLAY_NAME = 'Web Sphere Decoder'
  module Utils
    
    def showMessageDialog(options={})
      # Levels:
      #   default                      = 1
      #   JOptionPane::WARNING_MESSAGE = 2
      #   JOptionPane.ERROR_MESSAGE    = 3
      #   JOptionPane.PLAIN_MESSAGE    = 4
      JOptionPane.showMessageDialog(nil, options[:message] , options[:title], options[:level])
    end
    
  end
  
  class TabFactory
    
    include IMessageEditorTab
    include WebSphereHelper
    include Utils
    
    DISPLAY_NAME = 'WebSphereDecoder'
    
    
    def initialize(callbacks, editable)
      @callbacks = callbacks
      # Burp Suite useful helpers:
      @helper    = callbacks.get_helpers()
      # Create a Burp's plain text editor to use with this extension:
      @txt_input = callbacks.create_text_editor()
      # Indicates if the text editor is read-only or not:
      @editable  = editable
    end
    
    # String IMessageEditorTab::getTabCaption();
    #
    # getTabCaption: the tab name that will be displayed by Burp
    def getTabCaption
      DISPLAY_NAME
    end
    
    # java.awt.Component IMessageEditorTab::getUiComponent()
    #
    # component of the invoked tab, in our case, the component is (@txt_input: Text editor)
    def getUiComponent
      @txt_input.get_component()
    end
    
    # boolean IMessageEditorTab::isEnabled(byte[] content, boolean isRequest)
    #
    # isEnabled: this method is invoked each time Burp displays
    # a new message to check if the new custom tab should be displayed.
    # It should return a Boolean.
    def isEnabled(content, is_request)
      
      if content.nil? or content.empty?
        return false
      elsif is_request
        info = @helper.analyze_request(content)
      else
        info = @helper.analyze_response(content)
      end
      
      # @callbacks.issueAlert('isEnabled')
      # @callbacks.issueAlert content_type = info.getContentType
      # @callbacks.issueAlert headers = info.get_headers
      # @callbacks.issueAlert http_method = info.get_method
      # @callbacks.issueAlert parameters = info.get_parameters
      # @callbacks.issueAlert url = info.get_url
      
      # showMessageDialog(:title => 'info!', :message => "#{info}", :level => 1 )
      # showMessageDialog(:title => 'is_request!', :message => "#{is_request}", :level => 1 )
      # true
      web_sphere_url?(info, is_request, @callbacks)
    end
    
    # void IMessageEditorTab::setMessage(byte[] content, boolean isRequest)
    #
    # setMessage: this method is invoked each time a new message is
    # displayed in your custom tab. This method will take care of processing
    # the message. #setMessage method will fill it with the decrypted JSON into the displayed tab
    # def setMessage(content, is_request)
    #
    # end
    
    # byte[] IMessageEditorTab::getMessage()
    #
    # getMessage: this method is invoked each time you leave the custom tab.
    # It returns an array of bytes that will be used by Burp (see below).
    # def getMessage
    #
    # end
    
    # boolean IMessageEditorTab::isModified()
    #
    # isModified: this method is invoked after calling #getMessage and
    # if the editor tab is editable (in the Repeater tool for example).
    # It should return true if the message has been edited.
    # You simply use the value returned by #text_modified? of the text editor object
    def isModified
      @callbacks.issueAlert("isModified") if @txt_input.text_modified?
    end
  end
  
end


class BurpExtender
  include IBurpExtender
  include IMessageEditorTabFactory
  include GUI
  include GUI::Utils
  
  attr_reader :callbacks
  
  # void IBurpExtender::registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks
    
    callbacks.setExtensionName(DISPLAY_NAME)    # Set Extension name
    callbacks.registerMessageEditorTabFactory(self)         # Register 'IMessageEditorTabFactory' extension

    showMessageDialog({title: 'Welcome', message: 'Thanks for installing WebSphere Decoder', level: 1})
    
  end
  
  # IMessageEditorTab IMessageEditorTabFactory::createNewInstance(
  #   IMessageEditorController controller,
  #   boolean editable)
  #
  # #createNewInstance method. Because you will use the callbacks a lot, it is a good idea
  # to create an instance variable to easily access it inside JSONDecryptorTab
  def createNewInstance(controller, editable)
    TabFactory.new(@callbacks, editable)
  end


end
 
