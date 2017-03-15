package com.dotcms.csrf.filter;



import org.osgi.framework.BundleContext;
import com.dotmarketing.osgi.GenericBundleActivator;

public class Activator extends GenericBundleActivator {


  final static String FILTER_NAME = "csrfFilter";


  @SuppressWarnings("unchecked")
  public void start(BundleContext bundleContext) throws Exception {



    // putting this filter last becuase the CMSFilter does not interact with the back end
    // urls
    new TomcatServletFilterUtil().addFilter(FILTER_NAME, new CSRFFilter(), FilterOrder.LAST, "*");


  }



  public void stop(BundleContext context) {
    new TomcatServletFilterUtil().removeFilter(FILTER_NAME);

  }


}


