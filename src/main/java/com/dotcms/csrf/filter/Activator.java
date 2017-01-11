package com.dotcms.csrf.filter;



import com.dotcms.repackage.org.osgi.framework.BundleContext;
import com.dotmarketing.osgi.GenericBundleActivator;

public class Activator extends GenericBundleActivator {


  final static String FILTER_NAME = "helloWorldFilter";
  final static String SERVLET_NAME = "helloWorldServlet";

  @SuppressWarnings("unchecked")
  public void start(BundleContext bundleContext) throws Exception {



    // putting this filter last becuase the CMSFilter does not interact with the back end
    // urls
    new TomcatServletFilterUtil().addFilter(FILTER_NAME, new CSRFFilter(), FilterOrder.LAST, "*", "/helloWorld");


  }



  public void stop(BundleContext context) {
    new TomcatServletFilterUtil().removeServlet(SERVLET_NAME);
    new TomcatServletFilterUtil().removeFilter(FILTER_NAME);

  }


}


