'use strict';

module.exports = function (grunt) {

    // Load tasks from grunt-* dependencies in package.json
    require('load-grunt-tasks')(grunt);

    // Time how long tasks take
    require('time-grunt')(grunt);

    // Project configuration
    grunt.initConfig({
        exec: {
            emscripten: {
                command: 'python build.py'
            }
        },
        uglify: {
            dist: {
                options: {
                    compress: true,
                },
                files: {
                    'dist/capstone.min.js': [
                        'src/**/*.js'
                    ]
                }
            }
        },
        connect: {
            options: {
                port: 9001,
                livereload: 35729,
                hostname: 'localhost'
            },
            livereload: {
                options: {
                    open: true
                }
            }
        },
        watch: {
            livereload: {
                files: [
                    'index.html',
                    'dist/*.js'
                ],
                options: {
                    livereload: '<%= connect.options.livereload %>'
                }
            },
        }
    });

    // Project tasks
    grunt.registerTask('test', [

    ]);
    grunt.registerTask('build', [
        'exec:emscripten',
        'uglify'
    ]);
    grunt.registerTask('serve', [
        'connect',
        'watch'
    ]);
    grunt.registerTask('default', [
        'test',
        'build'
    ]);
};
