//
//  LeakDetectorInfoViewController.m
//  Leak Detector
//
//  Created by David Naylor on 3/11/13.
//  Copyright (c) 2013 David Naylor. All rights reserved.
//

#import "LeakDetectorInfoViewController.h"

@interface LeakDetectorInfoViewController ()

@end

@implementation LeakDetectorInfoViewController

@synthesize leakInfoDict = _leakInfoDict;
-(NSDictionary*)leakInfoDict {
    return _leakInfoDict;
}
-(void)setLeakInfoDict:(NSDictionary *)leakInfoDict {
    _leakInfoDict = leakInfoDict;
    [self.leakInfoOutlineView reloadItem:nil];
    [self.leakInfoOutlineView expandItem:nil expandChildren:YES];
}

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Initialization code here.
    }
    
    return self;
}


#pragma mark -
#pragma mark NSOutlineViewDataSource

-(NSArray*) infoSections
{
    return [NSArray arrayWithObjects:@"os", @"languages", @"browsers", @"google_queries", @"amazon_products", @"page_titles", @"email_locations", @"visited_domains", @"visited_subdomains", nil];
}

- (NSInteger)outlineView:(NSOutlineView *)outlineView numberOfChildrenOfItem:(id)item {
    
    if (item == nil) {
        if (self.leakInfoDict) {
            return [self infoSections].count;
        } else {
            return 0;
        }
    } else if ([[self infoSections] containsObject:item]) {
        id val = [self.leakInfoDict objectForKey:item];
        if ([val isKindOfClass:[NSArray class]]) {
            return ((NSArray*)val).count;
        } else {
            return 1;
        }
    } else {
        return -1; // No nested dicts for now
    }
}


- (BOOL)outlineView:(NSOutlineView *)outlineView isItemExpandable:(id)item {
    return (item == nil) ? YES : [[self infoSections] containsObject:item];
}


- (id)outlineView:(NSOutlineView *)outlineView child:(NSInteger)index ofItem:(id)item {    
    
    if (item == nil) {
        return [[self infoSections] objectAtIndex:index];
    } else if ([[self infoSections] containsObject:item]) {
        
        id val = [self.leakInfoDict objectForKey:item];
        if ([val isKindOfClass:[NSArray class]]) {
            return [((NSArray*)val) objectAtIndex:index];
        } else {
            return val;
        }
    } else {
        NSLog(@"Shouldn't be here");
        return nil; // No nested dicts for now
    }
}


- (id)outlineView:(NSOutlineView *)outlineView objectValueForTableColumn:(NSTableColumn *)tableColumn byItem:(id)item {
    return (item == nil) ? @"Info" : item;
}


@end
