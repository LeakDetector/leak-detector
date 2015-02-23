//
//  LeakDetectorPrettyViewController.m
//  Leak Detector
//
//  Created by David Naylor on 3/23/13.
//  Copyright (c) 2013 David Naylor. All rights reserved.
//

#import "LeakDetectorPrettyViewController.h"
#import "ImagePathWrapper.h"

@interface LeakDetectorPrettyViewController ()

-(NSString*) stringFromList:(NSArray*)list;

@end

@implementation LeakDetectorPrettyViewController

# pragma mark Properties
@synthesize leakInfoDict = _leakInfoDict;
-(void) setLeakInfoDict:(NSDictionary *)leakInfoDict {
    _leakInfoDict = leakInfoDict;
    
    // TODO: error checking
    NSArray* oses = [leakInfoDict objectForKey:@"os"];
    self.lblOS.stringValue = [self stringFromList:oses];
    
    NSArray* languages = [leakInfoDict objectForKey:@"languages"];
    self.lblLanguages.stringValue = [self stringFromList:languages];
    
    NSArray* browsers = [leakInfoDict objectForKey:@"browsers"];
    self.lblBrowsers.stringValue = [self stringFromList:browsers];
    
    self.googleSearches = [self.googleSearches setByAddingObjectsFromArray: [leakInfoDict objectForKey:@"google_queries"]];
    
    self.webPages = [self.webPages setByAddingObjectsFromArray:[leakInfoDict objectForKey:@"page_titles"]];
    
    self.amazonProducts = [self.amazonProducts setByAddingObjectsFromArray:[leakInfoDict objectForKey:@"amazon_products"]];
    
    NSArray* imagePaths = [leakInfoDict objectForKey:@"image_paths"];
    for (NSString* path in imagePaths) {
        ImagePathWrapper* wrapper = [[ImagePathWrapper alloc]init];
        wrapper.path = path;
        if ([self.images indexOfObject:wrapper] == NSNotFound)  // TODO: fix this
            [self.images addObject:wrapper];
    }
    [self.imageBrowser reloadData];
    
}

@synthesize googleSearches = _googleSearches;
-(NSSet*)googleSearches {
    if (!_googleSearches) {
        _googleSearches = [[NSSet alloc] init];
    }
    return _googleSearches;
}

@synthesize webPages = _webPages;
-(NSSet*)webPages {
    if (!_webPages) {
        _webPages = [[NSSet alloc] init];
    }
    return _webPages;
}

@synthesize amazonProducts = _amazonProducts;
-(NSSet*)amazonProducts {
    if (!_amazonProducts) {
        _amazonProducts = [[NSSet alloc] init];
    }
    return _amazonProducts;
}

@synthesize images = _images;



- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Initialization code here.
        
        self.images = [[NSMutableArray alloc] init];
        
        [self.imageBrowser setAnimates:YES];
    }
    
    return self;
}


#pragma mark Helper Methods
-(NSString*)stringFromList:(NSArray *)list {
    // TODO: Error checking
    if (list.count == 0)
        return @"";
    
    NSString* rv = list[0];
    for (int i = 1; i < list.count; i++) {
        rv = [rv stringByAppendingFormat:@", %@", list[i]];
    }
    return rv;
}


#pragma mark ImageBrowserDataSource
- (int) numberOfItemsInImageBrowser:(IKImageBrowserView *) view
{
    return [self.images count];
}

- (id) imageBrowser:(IKImageBrowserView *) view itemAtIndex:(int) index
{
    return [self.images objectAtIndex:index];
}

@end
