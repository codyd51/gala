#import <Cocoa/Cocoa.h>         // include the Cocoa Frameworks

@interface NSViewWithTopLeftCoordinateSystem : NSView
@end

@implementation NSViewWithTopLeftCoordinateSystem
- (BOOL)isFlipped {
    return YES;
}
@end

@interface ContentView : NSViewWithTopLeftCoordinateSystem
@end

@implementation ContentView
- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        NSString* imagePath = @"/Users/philliptennen/Documents/Jailbreak/gala/assets/boot_logo_for_gui.png";
        NSImage* image = [[NSImage alloc] initByReferencingFile:imagePath];
        NSLog(@"image %@", image);
        NSImageView* logo = [NSImageView imageViewWithImage:image];

        logo.frame = NSMakeRect(
            CGRectGetWidth(frame) * 0.13,
            CGRectGetHeight(frame) * 0.1,
            CGRectGetWidth(frame) * 0.75,
            CGRectGetHeight(frame) * 0.5
        );
        NSLog(@"logo %@", NSStringFromRect(logo.frame));
        [self addSubview:logo];

        CGSize buttonSize = CGSizeMake(
            CGRectGetWidth(frame) * 0.15,
            CGRectGetHeight(frame) * 0.1
        );
        CGFloat buttonsY = CGRectGetHeight(frame) * 0.8;
        CGFloat midX = CGRectGetMidX(frame);

        NSButton* jailbreakButton = [[NSButton alloc] initWithFrame:NSMakeRect(
            midX - (buttonSize.width * 1.5),
            buttonsY,
            buttonSize.width,
            buttonSize.height
        )];
        [self addSubview:jailbreakButton];
        [jailbreakButton setTitle: @"Jailbreak"];
        [jailbreakButton setBezelStyle:NSThickerSquareBezelStyle];

        NSButton* tetheredBootButton = [[NSButton alloc] initWithFrame:NSMakeRect(
                midX + (buttonSize.width * 0.5),
                buttonsY,
                buttonSize.width,
                buttonSize.height
        )];
        [self addSubview:tetheredBootButton];
        [tetheredBootButton setTitle: @"Tethered boot"];
        [tetheredBootButton setBezelStyle:NSThickerSquareBezelStyle];

    }
    return self;
}
@end

@interface LogsView : NSViewWithTopLeftCoordinateSystem
@end

@implementation LogsView
- (BOOL)isFlipped {
    return YES;
}

- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        NSTextView* inner = [[NSTextView alloc] initWithFrame:CGRectMake(0, 0, frame.size.width, frame.size.height)];
        inner.backgroundColor = [NSColor blackColor];
        [inner setTextColor:[NSColor whiteColor]];
        [inner setEditable:NO];
        [inner insertText:@"This is a test!"];
        [self addSubview:inner];
    }
    return self;
}
@end

@interface RunnerApp : NSObject <NSWindowDelegate>
@property (retain) NSWindow* window;
- (instancetype)init;
@end

@implementation RunnerApp
- (instancetype)init {
    if ((self = [super init])) {
        NSRect windowFrame = NSMakeRect(0, 0, 800, 500);

        NSWindowStyleMask windowStyleMask = NSWindowStyleMaskTitled
                                            |NSWindowStyleMaskClosable
                                            |NSWindowStyleMaskMiniaturizable;
        self.window = [[NSWindow alloc] initWithContentRect:windowFrame styleMask:windowStyleMask backing:NSBackingStoreBuffered defer:NO];
        [self.window center];
        self.window.title = @"gala - A4 tethered iOS 4 jailbreak";

        NSViewWithTopLeftCoordinateSystem* container = [[NSViewWithTopLeftCoordinateSystem alloc] initWithFrame:windowFrame];
        ContentView* controlsView = [[ContentView alloc] initWithFrame:NSMakeRect(
            0,
            0,
            windowFrame.size.width,
            windowFrame.size.height * 0.6
        )];
        [container addSubview:controlsView];

        LogsView* logsView = [[LogsView alloc] initWithFrame:NSMakeRect(
            windowFrame.origin.x,
            //CGRectGetMaxY(controlsView.frame),
                CGRectGetHeight(controlsView.frame),
            windowFrame.size.width,
            CGRectGetHeight(windowFrame) - CGRectGetHeight(controlsView.frame)
        )];
        [container addSubview:logsView];
        NSLog(@"logs view frame %@", NSStringFromRect(logsView.frame));

        self.window.contentView = container;
        self.window.delegate = self;
        //[self.window makeKeyAndOrderFront:nil];
        [self.window makeKeyWindow];
        [NSApp activateIgnoringOtherApps:YES];
        //[self.window setOrderedIndex:0];
        [self.window orderFrontRegardless];
        [self.window makeFirstResponder:nil];
    }
    return self;
}

/*
- (void)windowDidBecomeKey:(NSNotification *)notification {
    NSLog(@"Window did become key!");
}

- (void)windowDidUpdate:(NSNotification *)notification {
    NSLog(@"Window did update!");
}

- (void)windowDidResize:(NSNotification *)notification {
    NSLog(@"resize");
}

- (void)windowDidMiniaturize:(NSNotification *)notification {
    NSLog(@"mini");
}

- (void)windowDidMove:(NSNotification *)notification{NSLog(@"move");}
- (void)windowDidChangeScreen:(NSNotification *)notification{NSLog(@"changscreen");}
- (void)windowDidBecomeMain:(NSNotification *)notification{NSLog(@"didBecomeMain");}
- (void)windowDidExpose:(NSNotification *)notification{NSLog(@"didexpose");}
- (void)windowDidChangeOcclusionState:(NSNotification *)notification{NSLog(@"didChangeOcc");}
 */

@end

int main(int argc, char** argv) {
    RunnerApp* app = [[RunnerApp alloc] init];
    [[NSApplication sharedApplication] run];
    return 0;
}
