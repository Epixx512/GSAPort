# GSAPort

A tweak that uses an NSURLProtocol subclass to intercept Apple ID related login requests to run them through Apple's GrandSlam Authentication protocol. Works on iOS 6 and iOS 7, iOS 8 fails because it uses the NSURLSession system instead. This allows old iOS versions to get past Apple ID authentication, as they don't natively have GSA.

AI usage disclosure: GSAPort is partially AI assisted, with Claude Sonnet 5.5. AI assisted means parts of its code are corrected by AI, while most of the code is still human written. I do have Obj-C experience, and I have throughly checked all AI-touched portions of GSAPort. Most of the SRP algorithm comes from https://github.com/cocagne/pysrp, and AI was used to convert the more complicated components to the C equivalent. This does *NOT* mean the project is vibecoded!!

Big source of information: https://gist.github.com/JJTech0130/049716196f5f1751b8944d93e73d3452. Anisette server is https://github.com/Dadoum/anisette-v3-server.
