//
//  ImagePathWrapper.m
//  Leak Detector
//
//  Created by David Naylor on 3/23/13.
//  Copyright (c) 2013 David Naylor. All rights reserved.
//

#import "ImagePathWrapper.h"

@implementation ImagePathWrapper

@synthesize path = _path;

- (NSString *)  imageRepresentationType
{
    return IKImageBrowserPathRepresentationType;
}

- (id)  imageRepresentation
{
    return self.path;
}

- (NSString *) imageUID
{
    return self.path;
}

- (BOOL)isEqual:(id)other {
    if (other == self)
        return YES;
    
    NSLog(@"Comparing: %c\n", [self.path isEqualToString:((ImagePathWrapper*)other).path]);
    return [self.path isEqualToString:((ImagePathWrapper*)other).path]; // class-specific
}

@end
