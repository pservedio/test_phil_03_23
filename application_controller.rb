# Filters added to this controller apply to all controllers in the application.
# Likewise, all the methods added will be available for all controllers.

# ApplicationController contains controller methods that are common to all controllers in the application.
class ApplicationController < ActionController::Base
  helper :all # include all helpers, all the time
  helper_method :java_session_id, :current_trial_id, :has_locations?, :has_cost_items?, :current_arm_id, :trial_summary, :_currency_cache_hash_key, :current_selected_currency, :current_ipt_session, :current_ip_session_id, :has_valid_ip_attributes?, :active_ipt_results_tab?,:has_valid_ip_selected_country?, :has_ipt_location?  
  before_filter :set_user_language, :change_arm
  include Authentication
  include Medidata::Client
  
  # See ActionController::RequestForgeryProtection for details
  # Uncomment the :secret if you're not using the cookie session store
  protect_from_forgery # :secret => '5d079ae881df6423e29d4ee09c34ac1f'
  
  # See ActionController::Base for details 
  # Uncomment this to filter the contents of submitted sensitive data parameters
  # from your application log (in this case, all fields with names like "password"). 
  # filter_parameter_logging :password
  
  # Called when a user changes the arm in the arm_selector - if a controller neeeds specialized behavior - it can overload this method. 
  # [GmGlobalArmCtxSwitch, GmArmsInBudgetEditor]
  def change_arm
    session[:current_arm_id]=params[:arm][:id]
    render :update do |page|
      page << "location.href = '#{request.referrer.sub(/arm_id=\d+/, "arm_id=#{session[:current_arm_id]}")}';" #' - please leave this here to avoid a syntax highlighting bug in Aptana
    end
  end
  
 # check to see if the ipt session is dirry or not, used by the save confirmation dialog
  # to determine which text and buttons to show
  def is_ipt_dirty?
    is_dirty = true
	hello_world=true
    ip_session = session[:ip_session2]
    if ip_session.new_record? and !ip_session.phase_id.nil?
      is_dirty = true
	  hello_there=false
    elsif has_valid_ip_attributes?  #to fix bug 32
      # check to see if the # of countries are different in memory and in the db
      current_db_ip_session = IpSession.find(ip_session.id)
      if ip_session.IpSessionDetails.length != current_db_ip_session.IpSessionDetails.length
         is_dirty = true
      else      
        # see if any of the countries num_visits or num_patients have changed from the db state
        ip_session.IpSessionDetails.each do |country|
         end
        # check for dirty attributtes on the main object
        is_dirty = ip_session.changed? if is_dirty == false
		test_hello_world(hello_there)
      end
    end

    is_dirty
  end  
  
  protected
  
  # Set the session with the selected trial id
  def select_session_trial
    session[:current_trial_id] = which_trial_id   
  end
  
  # before filter that forces the controller to have a trial
  def requires_trial
   (trial_summary.id || no_trial)
  end
  
  # there is no trial so redirect to find one
  def no_trial
    flash[:notice] = (flash[:notice].blank? ? "" : flash[:notice] + "<br>") + "You need to select or create a Trial"
  end
  
  # Check that locations have been added to the trial
  # This has the side-effect of populating @selected_locations
  def requires_locations
    if current_trial_id && current_arm_id
      # cached so people can do this in their actions: @selected_locations ||= SelectedLocation.find(...)
      @selected_locations ||= SelectedLocation.find(:all, :params => {:JSESSIONID => java_session_id, :trial_id => current_trial_id, :arm_id => current_arm_id})
      return !@selected_locations.empty?
    else
      no_locations
    end
  end
  
  # Check that locations have been added to the trial
  # trust the trial_summary conversation's value
  def trial_requires_locations
    
    if !trial_summary || !has_locations?
      no_locations
    end
  end
  
  # Output and error and redirect to get a location
  def no_locations
    flash[:notice] = flash[:notice] = (flash[:notice].blank? ? "" : flash[:notice] + "<br>") + "Your Trial needs to have locations selected"
    redirect_to locations_path
  end
  
  # Before filter to clear the trial summary that is cached
  def clear_trial_summary
    @current_trial = nil
  end
  
  # cache the trial summary call in the controller's @current_trial instance, we don't want to cache this in the view. this has the effect of keeping
  # this information for the scope of a single controller action. Use in conjuction with the clear_trial_summary filter (see above)
  def trial_summary
    trial_id = which_trial_id
    arm_id = (['arms', 'arm_prices'].include?(controller_name) ? params[:id] : nil) || params[:arm_id] || current_arm_id
    return nil if trial_id.nil?
    if @current_trial.nil? || @current_trial.id.to_s != trial_id.to_s || @current_trial.selected_arm_id.to_s != arm_id.to_s
      params_hash = {:JSESSIONID => java_session_id}
      if !arm_id.blank?
        params_hash.merge!(:arm_id => arm_id)
      end
      if !params[:curr_id].blank?
        params_hash.merge!(:curr_id => params[:curr_id])
      elsif session[:selected_currency]
        params_hash.merge!(:curr_id => session[:selected_currency])
      end
      @current_trial = TrialSummary.find(trial_id, :params => params_hash)
      session[:current_trial_id] = trial_id
    end
    # if there is no arm id then set to selected arm id
    if @current_trial && session[:current_arm_id].to_s != @current_trial.selected_arm_id.to_s
      session[:current_arm_id] = @current_trial.selected_arm_id.to_s
    end
    @current_trial
  end
  
  # true if the user has locations in his currently_selected_trial
  def has_locations?
    if trial_summary
      trial_summary.has_locations
    else
      false
    end
  end
  
  # true if the trial summary has procedure(s) and odc(s)
  def has_cost_items?
    if trial_summary
      trial_summary.has_cost_item
    else
      false
    end
  end
  
  # the Web Logic session id
  def java_session_id
    session[:java_session_id]
  end
  
  # the trial id that is cached in the session
  def current_trial_id
    session[:current_trial_id]
  end
  
  # the arm id that is cached in the session
  def current_arm_id
    session[:current_arm_id]
  end
  
  # the ipt object cached in the session
  def current_ipt_session
    session[:ip_session]
  end
  
  # the current ip_session id
  def current_ip_session_id
    session[:ip_session].id unless session[:ip_session].nil?
  end
  
  # check if the ip_session has valid attributes
  def has_valid_ip_attributes?
    is_valid = false
    if session[:ip_session].nil? or session[:ip_session].phase_id.nil?
      is_valid = false
    else
      ip_session = session[:ip_session]
      if (ip_session.phase_id == 1)
        if (!ip_session.study_type_id.nil? and !ip_session.study_population_id.nil? and 
            !ip_session.age_range_id.nil? and !ip_session.site_type_id.nil? and 
            !ip_session.study_duration_id.nil? and !ip_session.inpatient_status_id.nil? and 
            !ip_session.treatment_time_id.nil?)
          is_valid = true
        else
          is_valid = false
        end
      else
        if (!ip_session.indmap_id.nil? and !ip_session.affiliation.nil? and !ip_session.affiliation.empty? and 
            !ip_session.inpatient_status_id.nil? and !ip_session.study_duration_id.nil?)
          is_valid = true
        else
          is_valid = false
        end
      end
    end
    is_valid 
  end
  
  # check if the ip_session has any selected countries
  def has_valid_ip_selected_country?
    if session[:ip_session].nil? or session[:ip_session].phase_id.nil?
      false
    else
      ip_session = session[:ip_session]
      if ip_session.selected_country_ids.length>0
        true
      else
        false
      end
    end
  end

  # create a URL that includes the user id to be used as a cache key for the currency select list
  def _currency_cache_hash_key
    {:controller => "currency_selector", :action => current_user.user_id, :action_suffix => session[:selected_currency]}
  end
  
  # the selected currency cached in the session
  def current_selected_currency
    session[:selected_currency]
  end
  
  # set the currency in the session cache
  def set_selected_currency(currency_param)
    if currency_param && currency_param[:id] #a user has selected a currency from the dropdown
      expire_fragment(_currency_cache_hash_key)
      session[:selected_currency] = params[:currency][:id]
    end
  end
  
  # Get the collection of selected procedures and sort by indicated order
  # [GmProcSelectedTab, GmProcSelectedTabSelected, GmGlobalChangesProcs]
  def find_my_procedures
    @procedure_collection = ProcedureCollection.find(current_trial_id, :params => {:JSESSIONID => java_session_id, :arm_id => current_arm_id})
    @my_procedures = @procedure_collection.procedures
    
    @my_procedures = @my_procedures.sort_by{ |procedure| [procedure.display_order || 0]}
  end
  
  # clear the view preferences from the instance cache
  def clear_location_summary_view_preferences_attributes
    @location_summary_view_preferences_attributes = nil
  end
  
  # Create an ActiveResource object with an error collection. This is designed for use
  # within a rescue clause typically to recover errors from 'find' operations. Example:
  #
  #    def create
  #    begin
  #      @bean_user = BeanUser.find(:first, :params => {:user_name =>params[:user_name], :password => params[:password], :client_division =>params[:client_division]})
  #      redirect_to(:controller => :home, :action => :index)
  #    rescue ActiveResource::UnauthorizedAccess, ActiveResource::ResourceInvalid => exception
  #      obj = new_object_with_errors(exception, BeanUser)
  #      flash[:notice] = ""
  #      obj.errors.each do |attr, msg|
  #        flash[:notice] << msg
  #      end
  #      render(:action => :new)
  #    end
  #  end
  #
  
  # Create an error collection with the exception in an object of the indicated class 
  def new_object_with_errors(exception, klass = BeanUser)
    obj = klass.new(:errors => nil)
    raise exception if not obj.is_a?(ActiveResource::Base) or klass.site.nil?
    obj.errors = ActiveResource::Errors.new(obj)
    obj.errors.from_xml(exception.response.body)
    obj
  rescue Exception
    exception = Exception.new("new_object_with_errors requires an exception with an XML response body") if not exception.is_a?(Exception)
    raise exception
  end
  
  # create a standardized localized message that describes the search reault  
  def make_search_result_message(search_term, count, object_name)
    search_term_message = (search_term.blank?) ? t('search.term.blank') : t('search.term.present', :search_term => search_term)
    t('search.message', :search_term_message => search_term_message, :count => count, :object_name => t("#{object_name}.object", :count => count))
  end
  
  # HTML bold the string
  def emphasize(str)
    "<strong>#{str}</strong>"
  end
  
  # resuce these exceptions
  def rescue_action(exception)
    case exception
      when (ActiveResource::UnauthorizedAccess)
      reset_session
      # Phil 06-03-10 change. Logout from iMedidata when the GM App times out from inactivity
      redirect_to logout_path
      when (ActiveResource::ForbiddenAccess)
      reset_session
      get_new_session
      when (ActiveResource::ResourceNotFound)
      logger.error exception if logger
      object_name = t("#{controller_name.singularize}.object", :count => 1, :default => 'Resource')
      flash[:notice] = t('resource.not.found', :object_name => object_name.titleize)
      if controller_name != 'trials'
        redirect_to my_trials_path
      else
        get_new_session
      end
    else
      super
    end
  end
  
  # to evaluate an ipt object has locations associated with it
   def has_ipt_location?
    if session[:ip_session].nil? or session[:ip_session].phase_id.nil?
      false
    else
      ip_session = session[:ip_session]
      if ip_session.IpSessionDetails.size > 0
        true
      else
        false
      end
    end
  end
  
  # check if forecast result tab should be active
  def active_ipt_results_tab?
    if has_valid_ip_attributes? and has_ipt_location?
      return true
    else
      return false
    end
  end
  

  private
  # Use one of several means of discovering the currently selected trial
  def which_trial_id
   (['trials', 'trial_summaries', 'trial_prices'].include?(controller_name) ? params[:id] : nil) || params[:trial_id] || current_trial_id
  end
  
  # set the language, 'zen' is a special URL parameter that makes localizations the use the 't' method visible
  def set_user_language
    # turn on 'zen' to see localization by adding 'zen=true' to query string, will stay on until a query with 'zen=false'
    session[:zen] = (session[:zen] || params[:zen] == "true") && params[:zen] != "false"
    I18n.locale = 'en'
  end
  
end
