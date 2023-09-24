// Copyright 2016 Google Inc.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Windows;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using OAuthDesktopApp;
using System.Linq;

namespace OAuthApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private async void button_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                KeycloakService keycloakService = new KeycloakService();
                keycloakService.OutputEvent += (_output) =>
                {
                    textBoxOutput.Text += _output + Environment.NewLine;
                };
                var token = await keycloakService.GetTokenAsync();
                this.Activate();
                MessageBox.Show(token);
            }
            catch (AggregateException ex)
            {
                this.Activate();
                MessageBox.Show(string.Concat(ex.InnerExceptions.SelectMany(_ex => _ex.Message + Environment.NewLine)));
            }
            catch (Exception ex)
            {
                this.Activate();
                MessageBox.Show(ex.Message);
            }
        }

    }
}
