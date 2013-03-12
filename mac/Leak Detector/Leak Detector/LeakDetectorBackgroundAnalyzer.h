//
//  LeakDetectorBackgroundAnalyzer.h
//  Leak Detector
//
//  Created by David Naylor on 3/11/13.
//  Copyright (c) 2013 David Naylor. All rights reserved.
//

#import <Foundation/Foundation.h>

@class LeakDetectorBackgroundAnalyzer;
@protocol AnalyzerActivityListener <NSObject>

-(void) analyzerDidStart:(LeakDetectorBackgroundAnalyzer*)analyzer;
-(void) analyzerDidFinish:(LeakDetectorBackgroundAnalyzer*)analyzer;

@end

@protocol LeakInfoDelegate <NSObject>

-(void) updateLeakInfo:(NSDictionary*)infoDict;

@end



@interface LeakDetectorBackgroundAnalyzer : NSObject

@property (atomic, weak) id<LeakInfoDelegate> infoDelegate;

-(void) startAnalyzeRealTime;
-(void) stopAnalyzeRealTime;
-(void) analyzeTrace:(NSString*)pcapFile;
-(void) addActivityListener:(id<AnalyzerActivityListener>)listener;
-(void) removeActivityListener:(id<AnalyzerActivityListener>)listener;

@end
