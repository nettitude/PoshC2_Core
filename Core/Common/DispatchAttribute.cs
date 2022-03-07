﻿using System;

namespace Core.Common
{
    [AttributeUsage(AttributeTargets.Method)]
    public class CoreDispatch : Attribute
    {
        public string Name { get; set; }
        public string Namespace { get; set; }
        public string[] Names { get; set; }
        public string Description { get; set; }
        public string Usage { get; set; }
        public string Help { get; set; }
    }
}