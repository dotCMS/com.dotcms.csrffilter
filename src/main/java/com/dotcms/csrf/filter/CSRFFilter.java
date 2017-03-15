package com.dotcms.csrf.filter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.dotcms.repackage.org.apache.commons.net.util.SubnetUtils;
import com.dotcms.util.HttpRequestDataUtil;
import com.dotmarketing.beans.Host;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.DotStateException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.SecurityLogger;
import com.dotmarketing.util.UtilMethods;

public class CSRFFilter implements Filter {

  Set<String> protectedUri = new HashSet<>();
  Set<String> validReferers = new HashSet<>();
  Set<String> whitelistUri = new HashSet<>();
  Set<String> whitelistHosts = new HashSet<>();
  Set<String> whitelistIps = new HashSet<>();
  
  @Override
  public void init(FilterConfig config) throws ServletException {
    
    Logger.info(CSRFFilter.class.getName(), "initing");
    String[] strings = PluginProperties.getPropertyArray("csrf.protect.uri");
    for (String x : strings) {
      Logger.info(this, "csrf protected:" + x);
      protectedUri.add(x);
    }

    strings = PluginProperties.getPropertyArray("csrf.whitelist.uri");
    for (String x : strings) {
      Logger.info(this, "csrf whitelisted:" + x);
      whitelistUri.add(x);
    }
    
    strings = PluginProperties.getPropertyArray("csrf.whitelist.ips");
    for (String x : strings) {
      Logger.info(this, "csrf whitelisted ip:" + x);
      whitelistIps.add(x);
    }
    
    strings = PluginProperties.getPropertyArray("csrf.valid.host.referers");
    for (String x : strings) {
      Logger.info(this, "csrf allowed referering domains:" + x);
      validReferers.add(x);
    }
    
    strings = PluginProperties.getPropertyArray("csrf.whitelist.host");
    for (String x : strings) {
      Logger.info(this, "csrf whitelisted domains:" + x);
      whitelistHosts.add(x);
    }
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {

    try {
      if (protectedUri(req)) {
        HttpServletRequest request = (HttpServletRequest) req;
        if (!allowedReferer(request)) {
          
          ((HttpServletResponse)res).sendError(403);
          return;
        }
      }
    } finally {
      UtilMethods.closeDbSilently();
    }
    chain.doFilter(req, res);
  }

  @Override
  public void destroy() {
    Logger.info(CSRFFilter.class.getName(),"destroy:" + this.getClass().getName());
  }


  private boolean protectedUri(ServletRequest request) {
    if (request instanceof HttpServletRequest) {
      HttpServletRequest req = (HttpServletRequest)request;
      if(hostWhiteListed(req)){
        return false;
      }
      if(ipWhiteListed(req)){
        return false;
      }
      for (String test : protectedUri) {
        if (req.getRequestURI().startsWith(test)) {
          if(!whitelistUri.contains(req.getRequestURI())){
            return true;
          }
        }
      }
    }
    return false;
  }

  private boolean allowedReferer(HttpServletRequest req) throws MalformedURLException {
    String refererHost = req.getServerName();
    String referer = req.getHeader("referer");
    if (referer != null) {
      URL url = new URL(referer);
      refererHost = url.getHost();
      if (validReferers.contains(refererHost)) {
        Logger.debug(this, "found in our allowed list" + refererHost);
        return true;
      }

      try {
        // Trying to find the host in our list of hosts
        Host foundHost = APILocator.getHostAPI().findByName(refererHost, APILocator.getUserAPI().getSystemUser(), false);
        if (!UtilMethods.isSet(foundHost) ) {
          foundHost = APILocator.getHostAPI().findByAlias(refererHost, APILocator.getUserAPI().getSystemUser(), false);
        }
        if (UtilMethods.isSet(foundHost)) {
          Logger.debug(this, "found in our host list" + refererHost);
          return true;
        }
      } catch (Exception e) {
        throw new DotStateException(e.getMessage(), e);
      }

    }
    String msg = "CSRFFilter ip:" + req.getRemoteAddr()+" has invalid referer:" + refererHost +  " url:" + req.getRequestURL();
    SecurityLogger.logInfo(this.getClass(), msg);
    Logger.warn(this.getClass(),  msg  );
    return false;
  }

  boolean hostWhiteListed(HttpServletRequest req){
    return whitelistHosts.contains(req.getServerName());
  }
  
  boolean ipWhiteListed(HttpServletRequest req){
    boolean allow=false;
    try{
      String visitorIp =  HttpRequestDataUtil.getIpAddress(req).getHostAddress();

      for(String ipOrNetMask : whitelistIps){
        if(ipOrNetMask==null) continue;
        if (ipOrNetMask.contains("/")) {
          allow = new SubnetUtils(ipOrNetMask).getInfo().isInRange(visitorIp);
        } else {
          allow = ipOrNetMask.equals(visitorIp);
        }
        if (allow) break;
      }


    }
    catch(Exception e){
      Logger.error(this.getClass(), e.getMessage(), e);
    }
    return allow;
  }
}
