//
//  ViewController.m
//  Gala Runner
//
//  Created by Phillip Tennen on 19/08/2023.
//

#import "ViewController.h"
#import "NSViewWithTopLeftCoordinateSystem.h"
#import "LogsView.h"
#import "ContentView.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    CGRect windowFrame = self.view.frame;
    NSViewWithTopLeftCoordinateSystem* container = [[NSViewWithTopLeftCoordinateSystem alloc] initWithFrame:windowFrame];
    [self.view addSubview:container];
    
    NSRect controlsViewFrame = NSMakeRect(
        0,
        0,
        windowFrame.size.width,
        windowFrame.size.height * 0.6
    );

    LogsView* logsView = [[LogsView alloc] initWithFrame:NSMakeRect(
        windowFrame.origin.x,
        CGRectGetHeight(controlsViewFrame),
        windowFrame.size.width,
        CGRectGetHeight(windowFrame) - CGRectGetHeight(controlsViewFrame)
    )];
    [container addSubview:logsView];

    ContentView* controlsView = [[ContentView alloc] initWithFrame:controlsViewFrame logsView:logsView];
    [container addSubview:controlsView];
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}


@end
