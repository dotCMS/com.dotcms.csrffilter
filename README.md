# dotCMS CsrfFilter

This filter can help provide a first line of protection from CSRF (Cross-site Request Forgery) type attacks against the dotCMS admin tool.  It works by checking the browser header "referer" and validating the referering host against the list of hosts being served in dotCMS. A config property (see below) can be set to add other hosts to that list or you can just add the allowed hostnames as aliases to your default host in dotCMS.

This Filter will only run via OSGi in dotCMS running under the Tomcat servlet container.  If you are running dotCMS in another app server, you will need to copy the logic of this plugin and provide it as a "static" plugin. 

It is provided as an OSGI plugin and can be configured and dropped on a running dotCMS server and initialize itself.  

Out of the box, there are 4 properties that can be adjusted by editing src/main/resources/plugin.properties

```properties
## Apply protection to these uris (begins with)
csrf.protect.uri=/c/portal,/api,/dotCMS,/html/,/html/ng,/dwr,/servlet,/DotAjaxDirector,/dotScheduledJobs,/dotTailLogServlet,/categoriesServlet,/JSONTags


## These are valid referering hosts (in addition to the hosts and aliases set in dotCMS)
csrf.valid.host.referers=testing.dotcms.com,localhost,127.0.0.1


## Always allow these domains to pass - even without passing a referer
csrf.whitelist.host=testing.dotcms.com,testing2.dotcms.com

## Always allow these urls to pass
csrf.whitelist.uri=/html/portal/login.jsp

```