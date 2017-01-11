# DOTCMS CSRFFILTER

This filter can help provide a first line of protection from CSRF (Cross-site Request Forgery) type attacks

It is provided as an OSGI plugin and can be configured and dropped on a running dotCMS server and initialize itself.  

Out of the box, there are 4 properties that can be adjusted by editing src/main/resources/plugin.properties

```
## Apply protection to these uris (begins with)
csrf.protect.uri=/c/portal,/api,/dotCMS,/html/,/html/ng,/dwr,/servlet,/DotAjaxDirector,/dotScheduledJobs,/dotTailLogServlet,/categoriesServlet,/JSONTags


## These are valid referering hosts (in addition to the hosts and aliases in dotCMS
csrf.valid.host.referers=testing.dotcms.com,localhost,127.0.0.1


## Always allow these domains to pass - even without passing a referer
csrf.whitelist.host=testing.dotcms.com,testing2.dotcms.com

## Always allow these urls to pass
csrf.whitelist.uri=/html/portal/login.jsp

```