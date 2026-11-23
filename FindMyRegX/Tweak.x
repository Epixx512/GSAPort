#import <Foundation/Foundation.h>

%group FindMyRegX
%hook AOSFindBaseAccount

- (id)apsEnvironmentConstant {
    NSString *raw = [(id)self valueForKey:@"apsEnvironment"];
    if ([raw isEqualToString:@"production"]) [(id)self setValue:@"Production" forKey:@"apsEnvironment"];
	else if ([raw isEqualToString:@"development"]) [(id)self setValue:@"Development" forKey:@"apsEnvironment"];
	else if ([raw isEqualToString:@"demo"]) [(id)self setValue:@"Demo" forKey:@"apsEnvironment"];
    id result = %orig;
    return result;
}

%end
%end

%ctor {
	if (kCFCoreFoundationVersionNumber >= 793.00) {
		%init(FindMyRegX);
	}
}