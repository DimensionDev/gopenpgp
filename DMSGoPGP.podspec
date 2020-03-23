Pod::Spec.new do |spec|
  spec.name         = "DMSGoPGP"
  spec.version      = "0.0.19"
  spec.summary      = "Mobile compatible OpenPGP library."

  spec.description  = <<-DESC
  Mobile compatible OpenPGP library, modified by Dimension
                   DESC
  spec.homepage     = "https://github.com/DimensionDev/gopenpgp"
  spec.license      = { :type => 'AGPL', :file => 'LICENSE' }
  spec.author             = { "jk234ert" => "ugling88@hotmail.com" }

  spec.ios.deployment_target = "9.0"
  spec.source       = { :git => "https://github.com/DimensionDev/gopenpgp.git", :tag => "#{spec.version}" }

  spec.header_dir = 'dist/iOS/DMSGoPGP.framework/Headers'
  # spec.source_files  = "Classes", "Classes/**/*.{h,m}"
  # spec.exclude_files = "Classes/Exclude"

  spec.ios.vendored_frameworks = 'dist/iOS/DMSGoPGP.framework'
  # spec.public_header_files = "Classes/**/*.h"


  # ――― Resources ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  A list of resources included with the Pod. These are copied into the
  #  target bundle with a build phase script. Anything else will be cleaned.
  #  You can preserve files from being cleaned, please don't preserve
  #  non-essential files like tests, examples and documentation.
  #

  # spec.resource  = "icon.png"
  # spec.resources = "Resources/*.png"

  # spec.preserve_paths = "FilesToSave", "MoreFilesToSave"


  # ――― Project Linking ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  Link your library with frameworks, or libraries. Libraries do not include
  #  the lib prefix of their name.
  #

  # spec.framework  = "SomeFramework"
  # spec.frameworks = "SomeFramework", "AnotherFramework"

  # spec.library   = "iconv"
  # spec.libraries = "iconv", "xml2"


  # ――― Project Settings ――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  If your library depends on compiler flags you can set them in the xcconfig hash
  #  where they will only apply to your library. If you depend on other Podspecs
  #  you can include multiple dependencies to ensure it works.

  # spec.requires_arc = true

  # spec.xcconfig = { "HEADER_SEARCH_PATHS" => "$(SDKROOT)/usr/include/libxml2" }
  # spec.dependency "JSONKit", "~> 1.4"

end
