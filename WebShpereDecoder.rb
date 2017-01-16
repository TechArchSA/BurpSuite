
VERSION         = '0.0.1 Alfa'
DEBUG           = true
APP_ID          = ''

# Ruby requires
require 'java'
require 'openssl'
require 'uri'
# Java imports
java_import javax.swing.JOptionPane
# Burp imports
java_import 'burp.IBurpExtender'
java_import 'burp.IBurpExtenderCallbacks'
java_import 'burp.IMessageEditorTabFactory'
java_import 'burp.IMessageEditorTab'
java_import 'burp.IExtensionHelpers'
java_import 'burp.IRequestInfo'
java_import 'burp.IResponseInfo'
java_import 'burp.IHttpRequestResponse'


module WebSphereHelper
  
  def setup_content_handler_url(url)
    uri = URI.parse(url)
    wps_path = uri.path.scan(/.*wps\//)
    if uri.scheme.include? 'http'
      request = "#{uri.scheme}://#{uri.host}/#{wps_path}/contenthandler?uri=state:#{uri.to_s}"
    else
      request = "#{uri.host}:#{uri.port}/#{wps_path}/contenthandler?uri=state:#{uri.to_s}"
    end
    
    request
  end
  
  def web_sphere_url?(url)
    path = URI.parse(url).path
    path.include?('/!ut/') ? true : false
  end
  
end

#
# BurpSuite GUI Factory
#
module GUI
  DISPLAY_NAME = 'Web Sphere Decoder'
  
  module Utils
  
    # showMessageDialog is an wrapper for 'JOptionPane.showMessageDialog' to popup a message box
    #
    # @param options [Hash]
    #   @option options Nil
    #   @option options :message [String]
    #   @option options :title [String]
    #   @option options :level [String]
    #                       Levels:
    #                         default                      = 1
    #                         JOptionPane::WARNING_MESSAGE = 2
    #                         JOptionPane.ERROR_MESSAGE    = 3
    #                         JOptionPane.PLAIN_MESSAGE    = 4
    def showMessageDialog(options={})
      JOptionPane.showMessageDialog(nil, options[:message] , options[:title], options[:level])
    end
    
  end
  class TabFactory
  
    include IMessageEditorTab
    include IExtensionHelpers
    include WebSphereHelper
    include Utils
    #
    # include IHttpRequestResponse
    
    DISPLAY_NAME = 'WebSphereDecoder'
    
    def initialize(callbacks, controller, editable)
      @extender_callbacks = callbacks
      # IMessageEditorController
      @controller         = controller
      # Burp Suite useful helpers: IExtensionHelpers
      @helper             = callbacks.get_helpers
      # Create a Burp's plain text editor to use with this extension:
      # ITextEditor from IBurpExtenderCallbacks.createTextEditor()
      @text_input         = callbacks.create_text_editor
      # Indicates if the text editor is read-only or not:
      @editable           = editable
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
      @text_input.getComponent() # get_component()
    end
  
    # boolean IMessageEditorTab::isEnabled(byte[] content, boolean isRequest)
    # isEnabled: this method is invoked each time Burp displays
    # a new message to check if the new custom tab should be displayed.
    # It should return a Boolean.
    #
    # @param [String] content The message that is about to be displayed, or a zero-length array if the existing message is to be cleared.
    # @param [Boolean] is_request Indicates whether the message is a request or a response.
    def isEnabled(content, is_request)
    
      if content.nil? or content.empty?
        return false
      elsif is_request
        info = @helper.analyzeRequest(@controller.getHttpService, content)
      else
        info = @helper.analyzeRequest(@controller.getHttpService, content)
      end
      @url = info.getUrl
      
      web_sphere_url? @url.to_s
    end
  
    # void IMessageEditorTab::setMessage(byte[] content, boolean isRequest)
    #
    # setMessage: this method is invoked each time a new message is
    # displayed in your custom tab. This method will take care of processing
    # the message.
    def setMessage(content, is_request)
      # To keep our changes on the text when we leave the tab
      return if @text_input.isTextModified
      
      # showMessageDialog(message: 'setMessage', title: 'setMessage', level: 1)
      
      @text_input.setText('setMessage 1')
      @text_input.setText = 'setMessage 2' # setup_content_handler_url(@url)
      @text_input.text('setMessage 3')
      @text_input.text = 'setMessage 4' # setup_content_handler_url(@url)
      @text_input.editable = @editable
    end
  
    # byte[] IMessageEditorTab::getMessage()
    #
    # getMessage: this method is invoked each time you leave the custom tab.
    # It returns an array of bytes that will be used by Burp (see below).
    def getMessage
      # showMessageDialog(message: 'getMessage', title: 'getMessage', level: 1)
      is_request = @text_input.getText
    end
  
    # boolean IMessageEditorTab::isModified()
    #
    # isModified: this method is invoked after calling #getMessage and
    # if the editor tab is editable (in the Repeater tool for example).
    # It should return true if the message has been edited.
    # You simply use the value returned by #text_modified? of the text editor object
    def isModified
      @extender_callbacks.issueAlert("isModified") if @txt_input.text_modified?
    end
  end

end

#
# BurpExtender, the main class to register all extensions and interfaces
#
class BurpExtender
  include IBurpExtender
  include IMessageEditorTabFactory
  include GUI
  include GUI::Utils
  
  attr_reader :extender_callbacks
  
  # void IBurpExtender::registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
  def registerExtenderCallbacks(callbacks)
    @extender_callbacks = callbacks
    
    @extender_callbacks.setExtensionName(DISPLAY_NAME)              # Set Extension name
    @extender_callbacks.registerMessageEditorTabFactory(self)       # Register 'IMessageEditorTabFactory' interface
    
    puts extension_info
    # greeting
  end
  
  # IMessageEditorTab IMessageEditorTabFactory::createNewInstance(
  #   IMessageEditorController controller,
  #   boolean editable)
  # createNewInstance method. Because you will use the callbacks a lot, it is a good idea
  # to create an instance variable to easily access it inside JSONDecryptorTab
  #
  # @param [Object] controller IMessageEditorController
  # @param [Object] editable  Indicates if the text editor is read-only or not
  def createNewInstance(controller, editable)
    TabFactory.new(@extender_callbacks, controller, editable)
  end
  
  
  private
  
  # Popup window, welcome!
  def greeting
    puts "Great! you've installed #{DISPLAY_NAME} successfully!"
    
    type, major_v, minor_v = @extender_callbacks.get_burp_version
    
    showMessageDialog(
        { title: 'Welcome',
          message:
                  "Thanks for installing #{DISPLAY_NAME}\n" +
                  'Burp Type: '    + "#{type}\n" +
                  'Burp Version: ' + "#{major_v}.#{minor_v}",
          level: 1
        })
  end

  # Extension information after installation
  def extension_info
    msg = "Extension: IBM WebShpere Rich-URL Decoder\n" +
          "Author: KING SABRI | @KINGSABRI\n" +
          "Github: https://github.com/TechArchSA/BurpSuite\n"
    puts msg
  end
  
end
 